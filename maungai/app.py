from __future__ import annotations

import argparse
from pathlib import Path
import sys
from typing import Callable

from .config import PIPELINE_PROFILES, PipelineConfig
from .pipeline import PipelineRunner, StepResult


class MaungAiApp:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GOLD = "\033[38;2;255;215;102m"
    CYAN = "\033[38;2;90;200;250m"
    BLUE = "\033[38;2;80;120;255m"
    SILVER = "\033[38;2;205;214;244m"
    MUTED = "\033[38;2;122;162;247m"
    PANEL = "\033[38;2;30;41;59m"
    SUCCESS = "\033[38;2;80;220;170m"
    WARNING = "\033[38;2;255;170;90m"
    RED = "\033[38;2;255;85;85m"
    RED_SOFT = "\033[38;2;210;60;60m"
    GREEN = "\033[38;2;80;255;140m"
    GREEN_SOFT = "\033[38;2;60;200;110m"

    def __init__(self, config: PipelineConfig):
        self.config = config
        self.runner = PipelineRunner(config)

    def run(self) -> int:
        self._clear_screen()
        while True:
            self._render_dashboard()
            choice = input("Pilih menu: ").strip()
            if choice == "0":
                print("\nKeluar dari MaungAi.")
                return 0
            if choice == "t":
                self._configure_target()
                continue
            if choice == "p":
                self._select_profile()
                continue
            if choice == "s":
                self._save_config()
                continue
            if choice == "l":
                self._load_config()
                continue
            if choice == "h":
                self._render_help()
                continue
            if choice == "8":
                self._run_and_render_many(self.runner.run_full_pipeline)
                continue
            if choice == "9":
                self._render_tools_status()
                continue
            if choice == "10":
                self._show_quick_stats()
                continue

            action = {
                "1": self.runner.run_asset_discovery,
                "2": self.runner.run_live_host_validation,
                "3": self.runner.run_endpoint_discovery,
                "4": self.runner.run_parameter_analysis,
                "5": self.runner.run_automated_checks,
                "6": self.runner.run_manual_review_queue,
                "7": self.runner.run_reporting,
            }.get(choice)

            if action is None:
                print("\nPilihan tidak valid.")
                self._pause()
                continue

            self._run_and_render_one(action)

    def _configure_target(self) -> None:
        print("\n[ Target Configuration ]")
        target = input(f"Domain [{self.config.target or 'example.com'}]: ").strip() or self.config.target
        scope = input(f"Scope [{self.config.scope or '*.example.com'}]: ").strip() or self.config.scope
        timeout_value = input(f"Timeout detik [{self.config.timeout_seconds}]: ").strip()
        historical_input = input(
            f"Gunakan historical URLs? [{'y' if self.config.allow_historical_urls else 'n'}]: "
        ).strip().lower()
        if not target:
            print("Target wajib diisi.")
        else:
            self.config.set_target(target, scope)
            if timeout_value.isdigit():
                self.config.timeout_seconds = int(timeout_value)
            if historical_input in {"y", "n"}:
                self.config.allow_historical_urls = historical_input == "y"
            print(f"Target aktif: {self.config.target}")
            print(f"Workspace : {self.config.project_root}")
            warnings = self.config.validate()
            if warnings:
                print("Warnings:")
                for warning in warnings:
                    print(f"  - {warning}")
        self._pause()

    def _run_and_render_one(self, action: Callable[[], StepResult]) -> None:
        result = action()
        self._render_result(result)
        self._pause()

    def _run_and_render_many(self, action: Callable[[], list[StepResult]]) -> None:
        results = action()
        for result in results:
            self._render_result(result)
            print("-" * 58)
        self._pause()

    def _render_dashboard(self) -> None:
        self._clear_screen()
        self._render_banner()
        print("")
        print("[ TARGET ]")
        print("┌─────────────────────────────────────────────────────────┐")
        print(f"│ Domain : {self._fit(self.config.target or 'Belum diatur', 47)}│")
        print(f"│ Scope  : {self._fit(self.config.scope or 'Belum diatur', 47)}│")
        status = "Ready" if self.config.is_ready else "Needs target"
        print(f"│ Status : {self._fit(status, 47)}│")
        print("└─────────────────────────────────────────────────────────┘")
        print("")
        print(f"Profile    : {self.config.profile}")
        print(f"Timeout    : {self.config.timeout_seconds}s")
        print(f"Historical : {'on' if self.config.allow_historical_urls else 'off'}")
        stats = self.runner.quick_stats()
        print(
            "Stats      : "
            f"subs={stats['subdomains']} live={stats['live_hosts']} "
            f"urls={stats['urls']} params={stats['query_urls']}"
        )
        print("")
        print("===================== MAIN MENU =====================")
        print("[t] Set Target")
        print("[p] Select Profile")
        print("[s] Save Config")
        print("[l] Load Config")
        print("[1] Asset Discovery")
        print("    - Subdomain Enumeration via subfinder")
        print("[2] Live Host Validation")
        print("    - HTTP/HTTPS validation via httpx")
        print("[3] Endpoint Discovery")
        print("    - katana + gau + waybackurls")
        print("[4] Parameter Analysis")
        print("    - query params + gf + uro fallback")
        print("[5] Automated Checks")
        print("    - nuclei modern template checks")
        print("[6] Manual Review Queue")
        print("    - checklist untuk authz, upload, API, logic")
        print("[7] Reporting")
        print("    - asset inventory + summary report")
        print("[8] Run Full Pipeline")
        print("[9] Tool Status")
        print("[10] Quick Stats")
        print("[h] Help")
        print("[0] Exit")
        print("=====================================================")
        print(f"Output root: {self.config.project_root}")
        print("")

    def _render_banner(self) -> None:
        status = "READY" if self.config.is_ready else "SET TARGET"
        status_color = self.SUCCESS if self.config.is_ready else self.WARNING
        if self._supports_unicode():
            lines = [
                (
                    f"{self.RED}{self.BOLD}"
                    " ███╗   ███╗ █████╗ ██╗   ██╗███╗   ██╗ ██████╗      █████╗ ██╗ "
                    f"{self.RESET}"
                ),
                (
                    f"{self.RED_SOFT}{self.BOLD}"
                    " ████╗ ████║██╔══██╗██║   ██║████╗  ██║██╔════╝     ██╔══██╗██║ "
                    f"{self.RESET}"
                ),
                (
                    f"{self.RED}{self.BOLD}"
                    " ██╔████╔██║███████║██║   ██║██╔██╗ ██║██║  ███╗    ███████║██║ "
                    f"{self.RESET}"
                ),
                (
                    f"{self.GREEN_SOFT}{self.BOLD}"
                    " ██║╚██╔╝██║██╔══██║██║   ██║██║╚██╗██║██║   ██║    ██╔══██║██║ "
                    f"{self.RESET}"
                ),
                (
                    f"{self.GREEN}{self.BOLD}"
                    " ██║ ╚═╝ ██║██║  ██║╚██████╔╝██║ ╚████║╚██████╔╝    ██║  ██║██║ "
                    f"{self.RESET}"
                ),
                (
                    f"{self.GREEN_SOFT}{self.BOLD}"
                    " ╚═╝     ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝ ╚═════╝     ╚═╝  ╚═╝╚═╝ "
                    f"{self.RESET}"
                ),
                "",
                (
                    f"{self.SILVER}{self.BOLD}"
                    "         Recon"
                    f"{self.GREEN} • {self.SILVER}"
                    "Discovery"
                    f"{self.GREEN} • {self.SILVER}"
                    "Automation"
                    f"{self.RED} • {self.SILVER}"
                    f"Research{self.RESET}"
                ),
                (
                    f"{self.MUTED}         Profile: {self.GOLD}{self.config.profile.upper()}{self.RESET}"
                    f"{self.MUTED}   Mode: {status_color}{status}{self.RESET}"
                    f"{self.MUTED}   Timeout: {self.CYAN}{self.config.timeout_seconds}s{self.RESET}"
                ),
            ]
        else:
            lines = [
                (
                    f"{self.RED}{self.BOLD}"
                    "MAUNGAI"
                    f"{self.RESET} "
                    f"{self.SILVER}- Recon - Discovery - Automation - Research{self.RESET}"
                ),
                (
                    f"{self.GREEN}Profile:{self.RESET} {self.GOLD}{self.config.profile.upper()}{self.RESET}  "
                    f"{self.GREEN}Mode:{self.RESET} {status_color}{status}{self.RESET}  "
                    f"{self.GREEN}Timeout:{self.RESET} {self.CYAN}{self.config.timeout_seconds}s{self.RESET}"
                ),
            ]
        for line in lines:
            print(line)

    def _supports_unicode(self) -> bool:
        encoding = (sys.stdout.encoding or "").lower()
        return "utf" in encoding or encoding == "cp65001"

    def _render_result(self, result: StepResult) -> None:
        status = "OK" if result.success else "FAILED"
        print(f"\n[{status}] {result.name}")
        if result.metrics:
            print("Metrics:")
            for key, value in result.metrics.items():
                print(f"  - {key}: {value}")
        if result.commands:
            print("Commands:")
            for command in result.commands:
                print(f"  - {command}")
        if result.files:
            print("Files:")
            for file in result.files:
                print(f"  - {file}")
        if result.notes:
            print("Notes:")
            for note in result.notes:
                print(f"  - {note}")
        if result.warnings:
            print("Warnings:")
            for warning in result.warnings:
                print(f"  - {warning}")

    def _render_tools_status(self) -> None:
        print("\n[ Tool Status ]")
        for name, available in self.runner.tools_status().items():
            marker = "ready" if available else "missing"
            print(f"- {name:<12} : {marker}")
        self._pause()

    def _select_profile(self) -> None:
        print("\n[ Scan Profile ]")
        for name, settings in PIPELINE_PROFILES.items():
            print(f"- {name:<9} : {settings.get('description', '')}")
        selected = input(f"Pilih profile [{self.config.profile}]: ").strip().lower() or self.config.profile
        if selected not in PIPELINE_PROFILES:
            print("Profile tidak dikenal.")
        else:
            self.config.set_profile(selected)
            print(f"Profile aktif: {self.config.profile}")
        self._pause()

    def _save_config(self) -> None:
        path = self.config.save()
        print(f"\nConfig tersimpan di: {path}")
        self._pause()

    def _load_config(self) -> None:
        default_path = self.config.config_file
        selected = input(f"\nPath config [{default_path}]: ").strip()
        path = Path(selected) if selected else default_path
        if not path.exists():
            print("File config tidak ditemukan.")
            self._pause()
            return
        loaded = PipelineConfig.load(path)
        self.config = loaded
        self.runner = PipelineRunner(self.config)
        print(f"Config berhasil dimuat dari: {path}")
        self._pause()

    def _show_quick_stats(self) -> None:
        print("\n[ Quick Stats ]")
        for key, value in self.runner.quick_stats().items():
            print(f"- {key:<16} : {value}")
        self._pause()

    def _render_help(self) -> None:
        print("\n[ Help ]")
        print("- Alur ideal: set target -> pilih profile -> run full pipeline -> review report.")
        print("- Profile fast cocok untuk triage cepat.")
        print("- Profile balanced cocok untuk workflow harian.")
        print("- Profile deep cocok untuk audit resmi pada scope yang lebih sempit.")
        print("- Jalankan hanya pada aset yang masuk scope dan berizin.")
        print(f"- Config snapshot akan disimpan ke: {self.config.config_file}")
        self._pause()

    def _pause(self) -> None:
        input("\nTekan Enter untuk lanjut...")

    def _clear_screen(self) -> None:
        print("\033c", end="")

    def _fit(self, value: str, width: int) -> str:
        truncated = value[:width]
        return truncated + (" " * (width - len(truncated)))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="maungai",
        description="Terminal workflow untuk recon pipeline terstruktur dan authorized testing.",
    )
    parser.add_argument("--target", help="Domain utama, contoh: example.com")
    parser.add_argument("--scope", help="Scope target, contoh: *.example.com")
    parser.add_argument(
        "--workspace-root",
        default="project",
        help="Folder root penyimpanan output pipeline",
    )
    parser.add_argument(
        "--profile",
        choices=sorted(PIPELINE_PROFILES.keys()),
        default="balanced",
        help="Preset scan: fast, balanced, atau deep",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=120,
        help="Timeout per command dalam detik",
    )
    parser.add_argument(
        "--config",
        help="Load konfigurasi dari file JSON yang pernah disimpan",
    )
    parser.add_argument(
        "--save-config",
        action="store_true",
        help="Simpan config snapshot lalu keluar",
    )
    parser.add_argument(
        "--no-history",
        action="store_true",
        help="Matikan pengambilan historical URLs",
    )
    parser.add_argument(
        "--step",
        choices=["assets", "live", "endpoints", "params", "scan", "manual", "report"],
        help="Jalankan satu tahap tanpa mode interaktif",
    )
    parser.add_argument(
        "--full-pipeline",
        action="store_true",
        help="Jalankan seluruh pipeline secara non-interaktif",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.config:
        config = PipelineConfig.load(Path(args.config))
    else:
        config = PipelineConfig(
            target=(args.target or "").strip(),
            scope=(args.scope or "").strip(),
            workspace_root=Path(args.workspace_root),
            profile=args.profile,
            timeout_seconds=args.timeout,
            allow_historical_urls=not args.no_history,
        )
    app = MaungAiApp(config)

    if args.target:
        app.config.target = args.target.strip()
    if args.scope:
        app.config.scope = args.scope.strip()
    if args.profile:
        app.config.set_profile(args.profile)
    if args.timeout:
        app.config.timeout_seconds = args.timeout
    if args.no_history:
        app.config.allow_historical_urls = False

    if args.save_config:
        print(app.config.save())
        return 0

    if args.full_pipeline:
        for result in app.runner.run_full_pipeline():
            app._render_result(result)
        return 0

    if args.step:
        step_map = {
            "assets": app.runner.run_asset_discovery,
            "live": app.runner.run_live_host_validation,
            "endpoints": app.runner.run_endpoint_discovery,
            "params": app.runner.run_parameter_analysis,
            "scan": app.runner.run_automated_checks,
            "manual": app.runner.run_manual_review_queue,
            "report": app.runner.run_reporting,
        }
        app._render_result(step_map[args.step]())
        return 0

    return app.run()
