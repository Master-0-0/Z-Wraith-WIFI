"""破解任务管理：统一调度 aircrack-ng / hashcat / 纯 Python 兜底。"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..config import Config
from ..events import EventBus
from ..models import CrackJob, Finding
from ..store import Store
from ..system.runner import Runner
from . import offline
from .tools import aircrack_crack, hashcat_crack

MAX_OFFLINE_CANDIDATES = 300_000


@dataclass
class CrackHandle:
    job_id: int
    task: asyncio.Task | None = None
    stop: bool = False
    extra: dict[str, Any] = field(default_factory=dict)


class CrackManager:
    def __init__(
        self,
        config: Config,
        store: Store,
        bus: EventBus,
        runner: Runner,
        session_id: int,
    ) -> None:
        self.config = config
        self.store = store
        self.bus = bus
        self.runner = runner
        self.session_id = session_id
        self._handles: dict[int, CrackHandle] = {}

    # ------------------------------------------------------------------ 查询
    @property
    def active(self) -> list[int]:
        return [jid for jid, h in self._handles.items() if h.task and not h.task.done()]

    def get(self, job_id: int) -> dict[str, Any] | None:
        return self.store.get_crack(job_id)

    # ------------------------------------------------------------------ 启动
    async def start(
        self,
        capture_id: int,
        *,
        wordlist: str | None = None,
        method: str = "auto",
    ) -> int:
        capture = self.store.get_capture(capture_id)
        if not capture:
            raise ValueError(f"抓包 #{capture_id} 不存在")
        path = Path(capture["path"])
        if not path.exists():
            raise FileNotFoundError(f"抓包文件不存在: {path}")

        wordlist_path = wordlist or self.config.wordlist
        resolved = self._resolve_method(method, path)
        if not self.config.is_live and method not in {"auto", "offline"}:
            self.bus.emit(
                "info", "crack", f"演示模式已忽略外部方法 {method}，改用内置离线校验"
            )
        job = CrackJob(
            capture_id=capture_id,
            method=resolved,
            wordlist=wordlist_path,
            status="running",
            started_at=time.time(),
        )
        job_id = self.store.add_crack(job)
        handle = CrackHandle(job_id=job_id)
        handle.extra["wordlist"] = wordlist_path
        self._handles[job_id] = handle
        handle.task = asyncio.create_task(self._run(handle, capture, resolved, wordlist_path))
        self.bus.emit(
            "attack",
            "crack",
            f"开始破解 #{job_id}（{resolved}）：{capture['ssid'] or '<隐藏>'}",
            job_id=job_id,
            capture_id=capture_id,
            wordlist=wordlist_path,
        )
        return job_id

    async def stop(self, job_id: int) -> bool:
        handle = self._handles.get(job_id)
        if not handle:
            return False
        handle.stop = True
        if handle.task and not handle.task.done():
            handle.task.cancel()
        self.store.update_crack(job_id, status="stopped", finished_at=time.time())
        self.bus.emit("warning", "crack", f"破解任务 #{job_id} 已停止")
        return True

    def _resolve_method(self, method: str, path: Path) -> str:
        if not self.config.is_live:
            # 演示模式不执行外部工具，统一走内置真实校验
            return "offline"
        if method != "auto":
            return method
        if path.suffix in {".22000", ".hccapx"}:
            return "hashcat" if _installed("hashcat") else "offline"
        if path.suffix in {".cap", ".pcap", ".pcapng"}:
            if _installed("aircrack-ng"):
                return "aircrack"
            return "hashcat" if _installed("hashcat") else "offline"
        return "offline"

    # ------------------------------------------------------------------ 执行
    async def _run(
        self,
        handle: CrackHandle,
        capture: dict[str, Any],
        method: str,
        wordlist: str,
    ) -> None:
        job_id = handle.job_id
        path = Path(capture["path"])
        log_parts: list[str] = []
        key: str | None = None
        status = "failed"

        def log(line: str) -> None:
            log_parts.append(line)
            if len(log_parts) > 400:
                del log_parts[:100]
            self.store.update_crack(job_id, log="\n".join(log_parts))

        def emit_line(line: str) -> None:
            if line.strip():
                log(line)
                self.bus.emit("debug", "crack", line, job_id=job_id)

        try:
            if method == "aircrack":
                key, out = await aircrack_crack(
                    self.runner,
                    path,
                    wordlist,
                    bssid=capture.get("bssid", ""),
                    timeout=self.config.crack_timeout,
                    on_line=emit_line,
                )
                log(out[-2000:])
                status = "found" if key else "exhausted"
            elif method == "hashcat":
                key, out = await hashcat_crack(
                    self.runner,
                    path,
                    wordlist,
                    self.config.run_path / f"crack-{job_id}",
                    timeout=self.config.crack_timeout,
                    on_line=emit_line,
                )
                status = "found" if key else "exhausted"
            else:
                key, status = await self._offline(handle, path, wordlist, log)
        except asyncio.CancelledError:
            status = "stopped"
            raise
        except Exception as exc:  # noqa: BLE001 - 需要把错误展示给用户
            log(f"破解异常: {exc}")
            self.bus.emit("error", "crack", f"破解任务 #{job_id} 失败: {exc}", job_id=job_id)
            status = "failed"
        finally:
            finished = time.time()
            self.store.update_crack(
                job_id,
                status=status,
                key=key or "",
                finished_at=finished,
                progress=1.0 if status in {"found", "exhausted"} else 0.0,
                log="\n".join(log_parts)[-12000:],
            )
            self._handles.pop(job_id, None)
            if key:
                self.bus.emit(
                    "success",
                    "crack",
                    f"✅ 口令已破解：{capture.get('ssid') or '<隐藏>'} → {key}",
                    job_id=job_id,
                    key=key,
                )
                self.store.add_finding(
                    Finding(
                        session_id=self.session_id,
                        title="Wi-Fi 口令被成功破解",
                        severity="critical",
                        bssid=capture.get("bssid", ""),
                        ssid=capture.get("ssid", ""),
                        detail=f"通过 {method} 破解得到 PSK，字典：{wordlist}",
                        category="crack",
                    )
                )
            elif status == "exhausted":
                self.bus.emit(
                    "warning", "crack", f"字典耗尽，未命中：{capture.get('ssid') or '<隐藏>'}", job_id=job_id
                )

    async def _offline(
        self,
        handle: CrackHandle,
        path: Path,
        wordlist: str,
        log,
    ) -> tuple[str | None, str]:
        """纯 Python 兜底破解（仅小字典）。"""
        entries = offline.parse_22000_file(path)
        if not entries:
            log("该文件不是 22000 格式，无法使用离线兜底；请安装 aircrack-ng/hashcat")
            return None, "failed"
        count = _count_candidates(wordlist)
        if count > MAX_OFFLINE_CANDIDATES:
            log(
                f"字典共 {count} 条，超过纯 Python 兜底上限 {MAX_OFFLINE_CANDIDATES}；"
                "请安装 aircrack-ng 或 hashcat 以获得可用的速度"
            )
            return None, "failed"
        self.bus.emit(
            "info",
            "crack",
            f"离线校验模式：{len(entries)} 条哈希 × {count} 条候选（PBKDF2 4096 轮/条）",
            job_id=handle.job_id,
        )

        def progress(done: int, total: int, rate: float) -> None:
            self.store.update_crack(handle.job_id, progress=min(0.99, done / max(1, total)))
            if done % 2000 == 0:
                self.bus.emit(
                    "debug", "crack", f"已尝试 {done} 条（{rate:.0f}/s）", job_id=handle.job_id
                )

        key, tried = await asyncio.to_thread(
            offline.crack,
            entries,
            wordlist,
            progress=progress,
            should_stop=lambda: handle.stop,
            max_candidates=MAX_OFFLINE_CANDIDATES,
        )
        log(f"离线校验完成：尝试 {tried} 条")
        if key:
            return key, "found"
        return None, "exhausted"


def _count_candidates(wordlist: str) -> int:
    """统计字典候选数（支持 .gz，超过上限即提前返回）。"""
    path = Path(wordlist)
    if not path.exists():
        return 0
    import gzip

    count = 0
    try:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:  # type: ignore[operator]
            for _ in fh:
                count += 1
                if count > MAX_OFFLINE_CANDIDATES:
                    break
    except OSError:
        return 0
    return count


def _installed(name: str) -> bool:
    from ..system.deps import is_installed

    return is_installed(name)
