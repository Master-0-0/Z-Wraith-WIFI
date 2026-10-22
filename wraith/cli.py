"""Wraith 命令行入口."""

from __future__ import annotations

import argparse
import asyncio
import sys
import time
import webbrowser
from pathlib import Path

import wraith
from .attacks.manager import AttackManager
from .authorization import AuthorizationGate
from .config import Config
from .crack.manager import CrackManager
from .events import EventBus
from .models import Session
from .recon.scanner import Scanner
from .report.generator import ReportGenerator
from .store import Store
from .system import deps
from .system.iface import IfaceManager
from .system.runner import Runner

C = {
    "reset": "\033[0m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "red": "\033[31m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "blue": "\033[34m",
    "magenta": "\033[35m",
    "cyan": "\033[36m",
}


def c(text: str, color: str) -> str:
    if not sys.stdout.isatty():
        return text
    return f"{C.get(color, '')}{text}{C['reset']}"


def banner(config: Config) -> None:
    mode = "演示 (demo)" if not config.is_live else "实机 (live)"
    print(
        c(
            f"""
  ╦ ╦╦═╗╔═╗╦╔╦╗╦ ╦
  ║║║╠╦╝╠═╣║ ║ ╠═╣
  ╚╩╝╩╚═╩ ╩╩ ╩ ╩ ╩   v{wraith.__version__}
""",
            "cyan",
        )
    )
    print(f"  Wi-Fi 渗透测试平台 · 模式：{c(mode, 'yellow' if config.is_live else 'green')}")
    print(f"  {c('仅限获得明确授权的安全测试', 'dim')}\n")


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_doctor(args: argparse.Namespace) -> int:
    report = deps.doctor()
    print(c("\n 工具依赖检查\n", "bold"))
    categories = {}
    for tool in report["tools"]:
        categories.setdefault(tool["category"], []).append(tool)
    for category, tools in categories.items():
        print(c(f"  [{category}]", "cyan"))
        for tool in tools:
            mark = c("●", "green") if tool["installed"] else c("○", "red")
            state = "已安装" if tool["installed"] else f"缺失（{tool['package']}）"
            print(f"    {mark} {tool['name']:<16} {tool['purpose']:<28} {c(state, 'dim' if tool['installed'] else 'yellow')}")
    print()
    py = report["python"]
    print(c(" Python 依赖", "cyan"))
    for module, ok in py["modules"].items():
        print(f"    {'●' if ok else '○'} {module}")
    print()
    if report["critical_missing"]:
        print(c(f"  缺少关键工具：{', '.join(report['critical_missing'])}", "red"))
        print(f"  安装建议：{deps.suggest_install(report['critical_missing'])}\n")
        return 1
    print(c(f"  环境就绪：{report['installed_count']}/{report['total_count']} 个工具可用\n", "green"))
    return 0


def cmd_interfaces(args: argparse.Namespace) -> int:
    async def run() -> int:
        runner = Runner(dry_run=False)
        manager = IfaceManager(runner)
        print(c("\n 无线网卡\n", "bold"))
        interfaces = await manager.list_interfaces()
        if not interfaces:
            print(c("  未检测到无线网卡（或缺少 iw）\n", "red"))
            return 1
        for iface in interfaces:
            flags = []
            if iface.monitor_capable:
                flags.append(c("monitor", "green"))
            if iface.ap_capable:
                flags.append(c("AP", "green"))
            print(
                f"  {c(iface.name, 'cyan'):<20} {iface.mode:<9} {iface.mac}  ch{iface.channel or '?'}"
                f"  {'/'.join(flags)}"
            )
        print(f"\n  root: {'是' if manager.is_root() else c('否（live 模式需要 sudo）', 'yellow')}\n")
        return 0

    return asyncio.run(run())


def cmd_web(args: argparse.Namespace) -> int:
    import uvicorn

    from .web.app import create_app

    config = _config_from_args(args)
    banner(config)
    app = create_app(config)
    url = f"http://{config.host}:{config.port}"
    print(f"  控制台：{c(url, 'cyan')}")
    print(f"  API 文档：{c(url + '/docs', 'cyan')}")
    print(f"  数据目录：{config.data_path}")
    print(f"  授权状态：{c('已授权' if config.authorized else '未授权（live 模式需在设置中确认）', 'green' if config.authorized else 'yellow')}\n")
    if args.open:
        webbrowser.open(url)
    uvicorn.run(app, host=config.host, port=config.port, log_level="warning" if not args.verbose else "info")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    async def run() -> int:
        config = _config_from_args(args)
        store, bus, runner, manager, gate, session_id = _bootstrap(config)
        bus.bind_loop(asyncio.get_running_loop())
        scanner = Scanner(config, store, bus, runner, manager, session_id)
        print(c(f"\n 开始扫描 · 接口 {config.iface or '自动'} · 模式 {config.mode}\n", "bold"))
        try:
            await scanner.start(config.iface or None, duration=args.duration, channel=args.channel)
        except PermissionError as exc:
            print(c(f"  {exc}\n", "red"))
            return 1
        deadline = time.time() + args.duration if args.duration else None
        try:
            while scanner.running:
                await asyncio.sleep(2)
                status = scanner.status()
                print(
                    f"\r  扫描中… {status['aps']} AP / {status['clients']} 客户端 / "
                    f"{status['seconds']}s",
                    end="",
                    flush=True,
                )
                if deadline and time.time() >= deadline:
                    break
        except KeyboardInterrupt:
            pass
        finally:
            await scanner.stop()
        print()
        snapshot = scanner.snapshot()
        if snapshot["aps"]:
            print(c("\n 发现接入点\n", "bold"))
            print(f"  {'SSID':<26} {'BSSID':<18} {'CH':>3}  {'安全':<12} {'信号':>5}  WPS")
            for ap in snapshot["aps"][:40]:
                print(
                    f"  {(ap['ssid'] or '<隐藏>')[:24]:<26} {ap['bssid']:<18} {ap['channel']:>3}  "
                    f"{ap['security']:<12} {ap['power'] or 0:>5}  {'是' if ap['wps'] else '-'}"
                )
        print(f"\n  会话 #{session_id} · 抓包目录 {config.capture_path}\n")
        store.end_session(session_id)
        store.close()
        return 0

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130


def cmd_targets(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    store = Store(config.db_path)
    sessions = store.list_sessions(20)
    if not sessions:
        print(c("  暂无会话，请先运行 wraith scan\n", "yellow"))
        return 1
    session = sessions[0]
    aps = []
    for candidate in sessions:
        candidate_aps = store.list_aps(candidate["id"])
        if candidate_aps:
            session, aps = candidate, candidate_aps
            break
    print(c(f"\n 会话 #{session['id']} · {session['name']} · {len(aps)} 个 AP\n", "bold"))
    print(f"  {'SSID':<26} {'BSSID':<18} {'CH':>3}  {'安全':<12} {'信号':>5}  WPS  WPS客户端")
    for ap in aps:
        print(
            f"  {(ap['ssid'] or '<隐藏>')[:24]:<26} {ap['bssid']:<18} {ap['channel']:>3}  "
            f"{ap['privacy'] or 'OPEN':<12} {ap['power'] or 0:>5}  "
            f"{'是' if ap['wps'] else '-':<3}"
        )
    print()
    store.close()
    return 0


def cmd_attack(args: argparse.Namespace) -> int:
    async def run() -> int:
        config = _config_from_args(args)
        store, bus, runner, manager, gate, session_id = _bootstrap(config)
        bus.bind_loop(asyncio.get_running_loop())
        if args.authorized:
            config.authorized = True
        attacks = AttackManager(
            config, store, bus, runner, manager, gate, session_id, scanner=None
        )
        params = {
            "bssid": args.bssid or "",
            "ssid": args.ssid or "",
            "channel": args.channel or 0,
            "security": args.security or "",
            "wps": args.wps,
        }
        for item in args.option or []:
            if "=" not in item:
                continue
            key, value = item.split("=", 1)
            params[key] = value
        try:
            job = await attacks.start(args.module, params)
        except (KeyError, ValueError, PermissionError, RuntimeError) as exc:
            print(c(f"\n  无法启动攻击：{exc}\n", "red"))
            store.close()
            return 1
        print(c(f"\n  攻击 {job.name} 已启动 · {job.id}\n", "bold"))
        while True:
            current = attacks.get(job.id)
            if not current or current.status not in {"queued", "running"}:
                break
            await asyncio.sleep(0.8)
        current = attacks.get(job.id)
        print(c("\n  执行日志", "cyan"))
        for line in (current.log if current else [])[-40:]:
            print(c(f"    {line}", "dim"))
        if current and current.result:
            result = current.result
            color = "green" if result.get("ok") else "yellow"
            print(c(f"\n  结果：{result.get('summary')}\n", color))
            if result.get("detail"):
                print(c(f"  详情：{result['detail']}\n", "dim"))
        if current and current.error:
            print(c(f"  错误：{current.error}\n", "red"))
        store.end_session(session_id)
        store.close()
        return 0 if current and current.status == "success" else 1

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130


def cmd_crack(args: argparse.Namespace) -> int:
    async def run() -> int:
        config = _config_from_args(args)
        config.wordlist = args.wordlist or config.wordlist
        probe = Store(config.db_path)
        capture = probe.get_capture(args.capture_id)
        probe.close()
        if not capture:
            print(c(f"\n  抓包 #{args.capture_id} 不存在\n", "red"))
            return 1
        store, bus, runner, manager, gate, session_id = _bootstrap(
            config, session_id=capture["session_id"]
        )
        bus.bind_loop(asyncio.get_running_loop())
        manager_cracks = CrackManager(config, store, bus, runner, session_id)
        try:
            job_id = await manager_cracks.start(args.capture_id, method=args.method, wordlist=config.wordlist)
        except (ValueError, FileNotFoundError) as exc:
            print(c(f"\n  {exc}\n", "red"))
            store.close()
            return 1
        print(c(f"\n  破解任务 #{job_id} · 字典 {config.wordlist}\n", "bold"))
        while job_id in manager_cracks.active:
            await asyncio.sleep(1)
        job = store.get_crack(job_id)
        if job and job["key"]:
            print(c(f"\n  ✅ 口令：{job['key']}\n", "green"))
        else:
            print(c(f"\n  未命中（状态：{job['status'] if job else 'unknown'}）\n", "yellow"))
        store.end_session(session_id)
        store.close()
        return 0 if job and job["key"] else 1

    try:
        return asyncio.run(run())
    except KeyboardInterrupt:
        return 130


def cmd_report(args: argparse.Namespace) -> int:
    config = _config_from_args(args)
    store = Store(config.db_path)
    sessions = store.list_sessions(1)
    if not sessions:
        print(c("  暂无会话数据\n", "yellow"))
        return 1
    session_id = args.session or sessions[0]["id"]
    generator = ReportGenerator(store, session_id)
    if args.format == "json":
        import json

        print(json.dumps(generator.json(), ensure_ascii=False, indent=2, default=str))
    elif args.format == "md":
        print(generator.markdown())
    elif args.format == "html":
        content = generator.html()
        if args.out:
            Path(args.out).write_text(content, encoding="utf-8")
            print(c(f"  已写入 {args.out}\n", "green"))
        else:
            print(content)
    else:
        paths = generator.save(args.out or config.report_path)
        for fmt, path in paths.items():
            print(f"  {fmt:<5} {path}")
    store.close()
    return 0


# ---------------------------------------------------------------------------
# 装配
# ---------------------------------------------------------------------------


def _config_from_args(args: argparse.Namespace) -> Config:
    config = Config.load()
    if getattr(args, "demo", False):
        config.mode = "demo"
    if getattr(args, "live", False):
        config.mode = "live"
    if getattr(args, "iface", None):
        config.iface = args.iface
    if getattr(args, "wordlist", None):
        config.wordlist = args.wordlist
    if getattr(args, "authorized", False):
        config.authorized = True
    if getattr(args, "operator", None):
        config.operator = args.operator
    if config.mode == "demo" and not getattr(args, "wordlist", None):
        demo_path = config.data_path / "wordlists" / "demo.txt"
        demo_path.parent.mkdir(parents=True, exist_ok=True)
        if not demo_path.exists():
            from .recon.demo import DEMO_WORDLIST

            demo_path.write_text("\n".join(DEMO_WORDLIST) + "\n", encoding="utf-8")
        config.wordlist = str(demo_path)
    if getattr(args, "port", None):
        config.port = args.port
    if getattr(args, "host", None):
        config.host = args.host
    config.ensure_dirs()
    return config


def _bootstrap(config: Config, *, session_id: int | None = None):
    from .system.iface import IfaceManager
    from .system.runner import Runner

    store = Store(config.db_path)
    bus = EventBus()
    runner = Runner(dry_run=not config.is_live)
    manager = IfaceManager(runner)
    gate = AuthorizationGate(config, bus)
    if session_id is None:
        session = Session(
            name=time.strftime("CLI %Y-%m-%d %H:%M"),
            mode=config.mode,
            iface=config.iface,
            operator=config.operator,
        )
        session_id = store.create_session(session)
    return store, bus, runner, manager, gate, session_id


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="wraith",
        description="Wraith — 面向授权测试的 Wi-Fi 渗透测试平台",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="示例：\n"
        "  wraith web --demo                 # 演示模式启动控制台\n"
        "  sudo wraith web --live --open     # 实机模式（需授权）\n"
        "  sudo wraith scan -i wlan0 -t 60   # 命令行扫描 60 秒\n"
        "  wraith doctor                     # 检查工具依赖\n",
    )
    parser.add_argument("--version", action="version", version=f"Wraith {wraith.__version__}")
    parser.add_argument("--iface", "-i", help="无线网卡名称")
    parser.add_argument("--wordlist", "-w", help="字典路径")
    parser.add_argument("--operator", help="操作者标识")
    parser.add_argument("--demo", action="store_true", help="强制演示模式")
    parser.add_argument("--live", action="store_true", help="强制实机模式（需 root）")
    parser.add_argument("--authorized", action="store_true", help="声明已获得授权（live 模式必需）")

    sub = parser.add_subparsers(dest="command", required=True)

    p_web = sub.add_parser("web", help="启动 Web 控制台")
    # 同时允许把常用开关写在子命令后（wraith web --demo）
    p_web.add_argument("--demo", action="store_true", default=argparse.SUPPRESS)
    p_web.add_argument("--live", action="store_true", default=argparse.SUPPRESS)
    p_web.add_argument("--authorized", action="store_true", default=argparse.SUPPRESS)
    p_web.add_argument("--iface", "-i", default=argparse.SUPPRESS)
    p_web.add_argument("--wordlist", "-w", default=argparse.SUPPRESS)
    p_web.add_argument("--operator", default=argparse.SUPPRESS)
    p_web.add_argument("--host", default=None)
    p_web.add_argument("--port", "-p", type=int, default=None)
    p_web.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    p_web.add_argument("--verbose", "-v", action="store_true")
    p_web.set_defaults(func=cmd_web)

    p_doctor = sub.add_parser("doctor", help="检查系统依赖")
    p_doctor.set_defaults(func=cmd_doctor)

    p_iface = sub.add_parser("interfaces", help="列出无线网卡")
    p_iface.set_defaults(func=cmd_interfaces)

    p_scan = sub.add_parser("scan", help="命令行扫描无线网络")
    p_scan.add_argument("--duration", "-t", type=float, default=None, help="扫描时长（秒）")
    p_scan.add_argument("--channel", "-c", type=int, default=None, help="锁定信道")
    p_scan.set_defaults(func=cmd_scan)

    p_targets = sub.add_parser("targets", help="列出最近会话发现的 AP")
    p_targets.set_defaults(func=cmd_targets)

    p_attack = sub.add_parser("attack", help="执行攻击模块")
    p_attack.add_argument("module", help="模块 ID（见 wraith web 的模块列表）")
    p_attack.add_argument("--bssid", "-b", required=True)
    p_attack.add_argument("--ssid", "-e", default="")
    p_attack.add_argument("--channel", "-c", type=int, default=0)
    p_attack.add_argument("--security", default="", help="WPA2/WPA3/OPEN/WEP…")
    p_attack.add_argument("--wps", action="store_true", help="目标启用 WPS")
    p_attack.add_argument(
        "--option", "-o", action="append", metavar="KEY=VALUE", help="模块参数，可多次指定"
    )
    p_attack.set_defaults(func=cmd_attack)

    p_crack = sub.add_parser("crack", help="对抓包执行离线破解")
    p_crack.add_argument("capture_id", type=int)
    p_crack.add_argument("--method", "-m", default="auto", choices=["auto", "aircrack", "hashcat", "offline"])
    p_crack.set_defaults(func=cmd_crack)

    p_report = sub.add_parser("report", help="生成评估报告")
    p_report.add_argument("--format", "-f", choices=["html", "json", "md"], default=None)
    p_report.add_argument("--out", "-o", default=None, help="输出文件或目录")
    p_report.add_argument("--session", "-s", type=int, default=None)
    p_report.set_defaults(func=cmd_report)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args) or 0)
    except KeyboardInterrupt:
        print(c("\n  已中断\n", "yellow"))
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
