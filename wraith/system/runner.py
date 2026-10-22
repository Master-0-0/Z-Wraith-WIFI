"""安全命令执行器：不使用 shell，统一超时/日志/脱敏，支持演示模式。"""

from __future__ import annotations

import asyncio
import os
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Sequence

from ..core.utils import redact_command


@dataclass
class CommandResult:
    cmd: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    simulated: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out

    @property
    def text(self) -> str:
        return (self.stdout + "\n" + self.stderr).strip()

    def to_dict(self) -> dict:
        return {
            "cmd": redact_command(self.cmd),
            "returncode": self.returncode,
            "stdout": self.stdout[-8000:],
            "stderr": self.stderr[-8000:],
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
            "simulated": self.simulated,
        }


LineHandler = Callable[[str], None]
AuditHook = Callable[[dict], None]


class Runner:
    """异步子进程执行器.

    - ``dry_run=True`` 时不真正执行，返回模拟成功结果（用于无 root 的演示/测试）。
    - 所有命令以 argv 列表传入，禁止 shell 拼接，避免注入。
    - ``on_line`` 回调可用于把输出实时推送到事件总线。
    """

    def __init__(
        self,
        dry_run: bool = False,
        audit: AuditHook | None = None,
        on_command: Callable[[CommandResult], None] | None = None,
    ) -> None:
        self.dry_run = dry_run
        self.audit = audit
        self.on_command = on_command
        self._env = {
            **os.environ,
            "LC_ALL": "C",
            "LANG": "C",
            "DEBIAN_FRONTEND": "noninteractive",
        }
        self._probe_lock = asyncio.Lock()

    # ------------------------------------------------------------------ 内部
    def _record(self, result: CommandResult) -> None:
        if self.audit:
            self.audit(
                {
                    "cmd": redact_command(result.cmd),
                    "returncode": result.returncode,
                    "duration": round(result.duration, 3),
                    "simulated": result.simulated,
                }
            )
        if self.on_command:
            try:
                self.on_command(result)
            except Exception:  # 日志失败不能影响攻击流程
                pass

    def _missing(self, cmd: Sequence[str]) -> CommandResult | None:
        from shutil import which

        if not cmd:
            return CommandResult(list(cmd), 127, stderr="空命令")
        binary = cmd[0]
        if os.path.sep in binary:
            exists = os.path.exists(binary)
        else:
            exists = which(binary) is not None
        if not exists:
            return CommandResult(
                list(cmd),
                127,
                stderr=f"命令不存在: {binary}（请先安装对应工具）",
                duration=0.0,
            )
        return None

    # ------------------------------------------------------------------ 探测
    async def query(self, cmd: Sequence[str], *, timeout: float = 8.0) -> CommandResult:
        """只读探测命令：即使处于演示模式也真实执行（不涉及发包）。

        用于枚举网卡、phy 能力等只读信息，让演示模式的硬件信息也保持真实。
        """
        if not self.dry_run:
            return await self.run(cmd, timeout=timeout)
        async with self._probe_lock:
            self.dry_run = False
            try:
                return await self.run(cmd, timeout=timeout)
            finally:
                self.dry_run = True

    # ------------------------------------------------------------------ 执行
    async def run(
        self,
        cmd: Sequence[str],
        *,
        timeout: float = 30.0,
        simulate_stdout: str = "",
        simulate_code: int = 0,
        on_line: LineHandler | None = None,
    ) -> CommandResult:
        cmd = [str(c) for c in cmd]
        started = time.monotonic()

        if self.dry_run:
            await asyncio.sleep(0.05)
            result = CommandResult(
                cmd,
                simulate_code,
                stdout=simulate_stdout,
                duration=time.monotonic() - started,
                simulated=True,
            )
            if on_line:
                for line in simulate_stdout.splitlines():
                    on_line(line)
            self._record(result)
            return result

        missing = self._missing(cmd)
        if missing:
            self._record(missing)
            return missing

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=self._env,
            )
        except (OSError, PermissionError) as exc:
            result = CommandResult(
                cmd, 126, stderr=f"无法启动 {cmd[0]}: {exc}", duration=time.monotonic() - started
            )
            self._record(result)
            return result

        out_chunks: list[str] = []
        err_chunks: list[str] = []
        timed_out = False

        async def _pump(stream: asyncio.StreamReader | None, sink: list[str]) -> None:
            if stream is None:
                return
            while True:
                raw = await stream.readline()
                if not raw:
                    break
                line = raw.decode("utf-8", "replace").rstrip("\n")
                sink.append(line)
                if on_line:
                    try:
                        on_line(line)
                    except Exception:
                        pass

        try:
            await asyncio.wait_for(
                asyncio.gather(_pump(proc.stdout, out_chunks), _pump(proc.stderr, err_chunks)),
                timeout=timeout,
            )
            await asyncio.wait_for(proc.wait(), timeout=max(1.0, timeout - (time.monotonic() - started)))
        except asyncio.TimeoutError:
            timed_out = True
            try:
                proc.terminate()
                await asyncio.wait_for(proc.wait(), timeout=3)
            except (ProcessLookupError, asyncio.TimeoutError):
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass

        result = CommandResult(
            cmd,
            proc.returncode if proc.returncode is not None else -1,
            stdout="\n".join(out_chunks),
            stderr="\n".join(err_chunks),
            duration=time.monotonic() - started,
            timed_out=timed_out,
        )
        self._record(result)
        return result

    async def run_checked(
        self,
        cmd: Sequence[str],
        *,
        timeout: float = 30.0,
        on_line: LineHandler | None = None,
    ) -> CommandResult:
        result = await self.run(cmd, timeout=timeout, on_line=on_line)
        if not result.ok:
            raise RuntimeError(
                f"命令失败 ({result.returncode}): {' '.join(redact_command(cmd))}\n{result.text[:800]}"
            )
        return result

    async def background(
        self,
        cmd: Sequence[str],
        *,
        on_line: LineHandler | None = None,
        delay: float = 0.5,
    ) -> asyncio.subprocess.Process | None:
        """启动常驻进程（hostapd / airodump / 门户）。返回进程句柄。"""
        cmd = [str(c) for c in cmd]
        if self.dry_run:
            await asyncio.sleep(0.05)
            return None
        missing = self._missing(cmd)
        if missing:
            self._record(missing)
            raise RuntimeError(missing.stderr)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
            env=self._env,
        )
        if on_line and proc.stdout:
            async def _pump() -> None:
                assert proc.stdout is not None
                while True:
                    raw = await proc.stdout.readline()
                    if not raw:
                        break
                    try:
                        on_line(raw.decode("utf-8", "replace").rstrip("\n"))
                    except Exception:
                        pass

            asyncio.create_task(_pump())
        await asyncio.sleep(delay)
        return proc

    @staticmethod
    async def terminate(proc: asyncio.subprocess.Process | None, timeout: float = 3.0) -> None:
        if proc is None or proc.returncode is not None:
            return
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except (ProcessLookupError, asyncio.TimeoutError):
            try:
                proc.kill()
            except ProcessLookupError:
                pass


def run_sync(coro: Awaitable) -> None:
    """供同步 CLI 调用的薄封装。"""
    asyncio.run(coro)  # type: ignore[arg-type]
