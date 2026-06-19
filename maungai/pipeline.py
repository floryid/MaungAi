from __future__ import annotations

from dataclasses import dataclass, field
import json
from pathlib import Path
import re
import shutil
import subprocess
import time
from typing import Iterable
from urllib.parse import parse_qsl, urlparse

from .config import PIPELINE_PROFILES, PipelineConfig


INTERESTING_PARAM_KEYWORDS = {
    "callback",
    "code",
    "continue",
    "data",
    "dest",
    "dir",
    "domain",
    "email",
    "file",
    "id",
    "image",
    "key",
    "next",
    "page",
    "path",
    "redirect",
    "reference",
    "return",
    "token",
    "upload",
    "uri",
    "url",
    "user",
}

API_HINTS = ("/api/", "/graphql", "/rest/", "/v1/", "/v2/", "/swagger", "/openapi")
STEP_ORDER = ("assets", "live", "endpoints", "params", "scan", "manual", "report")


@dataclass
class StepResult:
    name: str
    commands: list[str] = field(default_factory=list)
    files: list[Path] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    metrics: dict[str, int] = field(default_factory=dict)
    success: bool = True
    duration_seconds: float = 0.0
    log_file: Path | None = None


class PipelineRunner:
    def __init__(self, config: PipelineConfig):
        self.config = config

    @property
    def project_root(self) -> Path:
        return self.config.project_root

    @property
    def raw_root(self) -> Path:
        return self.project_root / "raw"

    @property
    def logs_root(self) -> Path:
        return self.project_root / "logs"

    def ensure_structure(self) -> None:
        for folder in [
            self.project_root / "assets",
            self.project_root / "endpoints",
            self.project_root / "parameters",
            self.project_root / "findings" / "info",
            self.project_root / "findings" / "low",
            self.project_root / "findings" / "medium",
            self.project_root / "findings" / "high",
            self.project_root / "screenshots",
            self.project_root / "reports",
            self.raw_root,
            self.logs_root,
        ]:
            folder.mkdir(parents=True, exist_ok=True)

    def asset_files(self) -> dict[str, Path]:
        return {
            "subdomains": self.project_root / "assets" / "subdomains.txt",
            "live": self.project_root / "assets" / "live.txt",
            "technologies": self.project_root / "assets" / "technologies.txt",
            "dns": self.project_root / "assets" / "dns.txt",
        }

    def endpoint_files(self) -> dict[str, Path]:
        return {
            "urls": self.project_root / "endpoints" / "urls.txt",
            "js": self.project_root / "endpoints" / "js.txt",
            "api": self.project_root / "endpoints" / "api.txt",
            "interesting": self.project_root / "endpoints" / "interesting.txt",
        }

    def parameter_files(self) -> dict[str, Path]:
        return {
            "query": self.project_root / "parameters" / "query.txt",
            "post": self.project_root / "parameters" / "post.txt",
            "hidden": self.project_root / "parameters" / "hidden.txt",
            "gf_xss": self.project_root / "parameters" / "gf_xss.txt",
            "gf_sqli": self.project_root / "parameters" / "gf_sqli.txt",
            "gf_ssrf": self.project_root / "parameters" / "gf_ssrf.txt",
            "priority_params": self.project_root / "parameters" / "priority.txt",
        }

    def quick_stats(self) -> dict[str, int]:
        assets = self.asset_files()
        endpoints = self.endpoint_files()
        params = self.parameter_files()
        return {
            "subdomains": len(self._read_lines(assets["subdomains"])),
            "live_hosts": len(self._read_lines(assets["live"])),
            "urls": len(self._read_lines(endpoints["urls"])),
            "api_urls": len(self._read_lines(endpoints["api"])),
            "query_urls": len(self._read_lines(params["query"])),
            "priority_params": len(self._read_lines(params["priority_params"])),
        }

    def run_asset_discovery(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        files = self.asset_files()
        result = StepResult(name="Asset Discovery", files=[files["subdomains"], files["dns"]])
        self._safe_write(files["subdomains"], "")
        self._safe_write(files["dns"], "")

        if not self.config.is_ready:
            result.success = False
            result.warnings.append("Target belum diset.")
            return self._finalize_result("assets", result, started)

        command = ["subfinder", "-d", self.config.target, "-silent"]
        command_result = self._run_command(command, raw_name="subfinder.txt")
        result.commands.append(self._display_command(command))

        if command_result is None:
            self._safe_write(files["subdomains"], f"{self.config.target}\n")
            result.warnings.append("subfinder tidak ditemukan, file fallback dibuat dari target utama.")
        else:
            output_lines = self._clean_lines(command_result.stdout.splitlines())
            if not output_lines:
                output_lines = [self.config.target]
                result.warnings.append("subfinder tidak mengembalikan data, target utama dipakai sebagai fallback.")
            self._write_lines(files["subdomains"], output_lines)

        subdomains = self._read_lines(files["subdomains"])
        self._write_lines(files["dns"], [self._guess_dns_record(line) for line in subdomains])
        result.metrics["subdomains"] = len(subdomains)
        result.notes.append(f"Subdomain tersimpan ke {files['subdomains']}")
        result.notes.append("DNS inventory dasar dibuat untuk memudahkan triage awal.")
        return self._finalize_result("assets", result, started)

    def run_live_host_validation(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        files = self.asset_files()
        result = StepResult(name="Live Host Validation", files=[files["live"], files["technologies"]])
        subdomains = self._read_lines(files["subdomains"])
        if not subdomains and self.config.target:
            subdomains = [self.config.target]

        self._safe_write(files["live"], "")
        self._safe_write(files["technologies"], "")

        if not subdomains:
            result.success = False
            result.warnings.append("Belum ada aset untuk divalidasi.")
            return self._finalize_result("live", result, started)

        temp_input = self.project_root / "assets" / ".httpx-input.txt"
        self._write_lines(temp_input, subdomains)

        live_cmd = ["httpx", "-silent", "-l", str(temp_input), *self._profile_list("httpx_extra_args")]
        live_result = self._run_command(live_cmd, raw_name="httpx-live.txt")
        result.commands.append(self._display_command(live_cmd))

        if live_result is None:
            self._write_lines(files["live"], subdomains)
            result.warnings.append("httpx tidak ditemukan, seluruh aset dianggap hidup untuk workflow lokal.")
        else:
            live_hosts = self._clean_lines(live_result.stdout.splitlines())
            self._write_lines(files["live"], live_hosts)
            result.metrics["live_hosts"] = len(live_hosts)
            result.notes.append(f"Host hidup: {len(live_hosts)}")

        tech_cmd = [
            "httpx",
            "-silent",
            "-tech-detect",
            "-status-code",
            "-title",
            "-l",
            str(files["live"]),
        ]
        tech_result = self._run_command(tech_cmd, raw_name="httpx-tech.txt")
        result.commands.append(self._display_command(tech_cmd))

        if tech_result is None:
            result.warnings.append("Mode fingerprinting dilewati karena httpx tidak tersedia.")
        else:
            self._write_lines(files["technologies"], self._clean_lines(tech_result.stdout.splitlines()))

        temp_input.unlink(missing_ok=True)
        return self._finalize_result("live", result, started)

    def run_endpoint_discovery(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        asset_files = self.asset_files()
        files = self.endpoint_files()
        result = StepResult(name="Endpoint Discovery", files=list(files.values()))
        live_hosts = self._read_lines(asset_files["live"])
        collected_urls: list[str] = []

        if live_hosts:
            temp_hosts = self.project_root / "endpoints" / ".katana-input.txt"
            self._write_lines(temp_hosts, live_hosts)
            katana_cmd = [
                "katana",
                "-list",
                str(temp_hosts),
                "-silent",
                "-depth",
                str(self.config.profile_settings.get("crawler_depth", 4)),
                *self._profile_list("katana_extra_args"),
            ]
            katana_result = self._run_command(katana_cmd, raw_name="katana.txt")
            result.commands.append(self._display_command(katana_cmd))
            if katana_result is None:
                result.warnings.append("katana tidak ditemukan, crawling aktif dilewati.")
            else:
                collected_urls.extend(katana_result.stdout.splitlines())
            temp_hosts.unlink(missing_ok=True)
        else:
            result.warnings.append("Belum ada live host, crawling aktif dilewati.")

        if self.config.allow_historical_urls and bool(self.config.profile_settings.get("use_historical_urls", True)):
            for tool_name, command in [
                ("gau", ["gau", "--subs", self.config.target]),
                ("waybackurls", ["waybackurls", self.config.target]),
            ]:
                tool_result = self._run_command(command, raw_name=f"{tool_name}.txt")
                result.commands.append(self._display_command(command))
                if tool_result is None:
                    result.warnings.append(f"{tool_name} tidak ditemukan, historical URL dilewati.")
                    continue
                collected_urls.extend(tool_result.stdout.splitlines())

        unique_urls = self._dedupe_urls(collected_urls)
        js_urls = [url for url in unique_urls if url.lower().endswith(".js")]
        api_urls = [url for url in unique_urls if any(hint in url.lower() for hint in API_HINTS)]
        interesting_urls = self._interesting_urls(unique_urls)
        self._write_lines(files["urls"], unique_urls)
        self._write_lines(files["js"], js_urls)
        self._write_lines(files["api"], api_urls)
        self._write_lines(files["interesting"], interesting_urls)
        result.metrics["urls"] = len(unique_urls)
        result.metrics["js_urls"] = len(js_urls)
        result.metrics["api_urls"] = len(api_urls)
        result.notes.append(f"Endpoint unik: {len(unique_urls)}")
        result.notes.append(f"Interesting endpoints: {len(interesting_urls)}")
        return self._finalize_result("endpoints", result, started)

    def run_parameter_analysis(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        files = self.parameter_files()
        urls_file = self.endpoint_files()["urls"]
        result = StepResult(name="Parameter Analysis", files=list(files.values()))
        urls = self._read_lines(urls_file)

        query_urls: list[str] = []
        hidden_candidates: list[str] = []
        priority_urls: list[str] = []
        seen_params: set[str] = set()

        for url in urls:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            query_urls.append(url)
            interesting_in_url = False
            for key, _ in parse_qsl(parsed.query, keep_blank_values=True):
                key_lower = key.lower()
                if key_lower not in seen_params:
                    seen_params.add(key_lower)
                    if any(keyword in key_lower for keyword in INTERESTING_PARAM_KEYWORDS):
                        hidden_candidates.append(key_lower)
                if any(keyword in key_lower for keyword in INTERESTING_PARAM_KEYWORDS):
                    interesting_in_url = True
            if interesting_in_url:
                priority_urls.append(url)

        deduped_queries = self._dedupe_urls(query_urls)
        deduped_priority = self._dedupe_urls(priority_urls)
        self._write_lines(files["query"], deduped_queries)
        self._write_lines(files["hidden"], sorted(hidden_candidates))
        self._write_lines(files["priority_params"], deduped_priority)
        self._safe_write(
            files["post"],
            "# Isi manual dari proxy/Burp request capture untuk parameter POST.\n"
            "# Contoh: endpoint | method | param1,param2,param3\n",
        )

        filtered_for_gf = deduped_queries
        if self._tool_exists("uro"):
            uro_result = self._run_command(["uro"], stdin_text="\n".join(deduped_queries) + "\n", raw_name="uro.txt")
            result.commands.append("uro < query.txt")
            if uro_result is not None:
                filtered_for_gf = self._clean_lines(uro_result.stdout.splitlines())
        else:
            result.warnings.append("uro tidak ditemukan, deduplikasi parameter memakai logika internal Python.")

        for pattern_name, output_file in [
            ("xss", files["gf_xss"]),
            ("sqli", files["gf_sqli"]),
            ("ssrf", files["gf_ssrf"]),
        ]:
            if self._tool_exists("gf"):
                gf_result = self._run_command(
                    ["gf", pattern_name],
                    stdin_text="\n".join(filtered_for_gf) + "\n",
                    raw_name=f"gf-{pattern_name}.txt",
                )
                result.commands.append(f"gf {pattern_name} < query.txt")
                if gf_result is not None:
                    self._write_lines(output_file, self._clean_lines(gf_result.stdout.splitlines()))
                    continue
            fallback = self._fallback_param_filter(filtered_for_gf, pattern_name)
            self._write_lines(output_file, fallback)
            result.warnings.append(f"gf {pattern_name} tidak ditemukan, fallback pattern internal dipakai.")

        result.metrics["query_urls"] = len(deduped_queries)
        result.metrics["priority_params"] = len(deduped_priority)
        result.notes.append(f"URL berparameter: {len(deduped_queries)}")
        result.notes.append(f"Priority params: {len(deduped_priority)}")
        return self._finalize_result("params", result, started)

    def run_automated_checks(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        target_file = self.endpoint_files()["interesting"]
        if not target_file.exists() or not self._read_lines(target_file):
            target_file = self.endpoint_files()["urls"]
        if not target_file.exists() or not self._read_lines(target_file):
            target_file = self.asset_files()["live"]

        result = StepResult(
            name="Automated Checks",
            files=[
                self.project_root / "findings" / "info" / "nuclei-info.txt",
                self.project_root / "findings" / "low" / "nuclei-low.txt",
                self.project_root / "findings" / "medium" / "nuclei-medium.txt",
                self.project_root / "findings" / "high" / "nuclei-high.txt",
            ],
        )

        if not target_file.exists() or not self._read_lines(target_file):
            result.success = False
            result.warnings.append("Belum ada target valid untuk scan otomatis.")
            return self._finalize_result("scan", result, started)

        if not self._tool_exists("nuclei"):
            for file in result.files:
                self._safe_write(file, "# nuclei belum tersedia di environment ini.\n")
            result.warnings.append("nuclei tidak ditemukan, placeholder findings dibuat.")
            return self._finalize_result("scan", result, started)

        severity_map = {
            "info": self.project_root / "findings" / "info" / "nuclei-info.txt",
            "low": self.project_root / "findings" / "low" / "nuclei-low.txt",
            "medium": self.project_root / "findings" / "medium" / "nuclei-medium.txt",
            "high": self.project_root / "findings" / "high" / "nuclei-high.txt",
        }
        findings_total = 0
        for severity, output_file in severity_map.items():
            command = [
                "nuclei",
                "-as",
                "-l",
                str(target_file),
                "-severity",
                severity,
                *self._profile_list("nuclei_extra_args"),
            ]
            nuclei_result = self._run_command(command, raw_name=f"nuclei-{severity}.txt")
            result.commands.append(self._display_command(command))
            if nuclei_result is None:
                self._safe_write(output_file, f"# nuclei gagal dijalankan untuk severity {severity}.\n")
                result.warnings.append(f"Scan severity {severity} gagal dijalankan.")
                continue
            lines = self._clean_lines(nuclei_result.stdout.splitlines())
            self._write_lines(output_file, lines)
            result.metrics[f"nuclei_{severity}"] = len(lines)
            findings_total += len(lines)

        result.notes.append(f"Total automated findings: {findings_total}")
        return self._finalize_result("scan", result, started)

    def run_manual_review_queue(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        queue_file = self.project_root / "reports" / "manual-review.md"
        content = "\n".join(
            [
                "# Manual Review Queue",
                "",
                f"- Target: {self.config.target or 'belum diset'}",
                f"- Scope: {self.config.scope or 'belum diset'}",
                f"- Profile: {self.config.profile}",
                "",
                "## Prioritas Verifikasi",
                "- Authentication flows",
                "- Authorization review",
                "- File upload features",
                "- Business logic flows",
                "- API access controls",
                "- Client-side review",
                "- Sensitive file exposure",
                "- Redirect and SSRF sinks",
                "",
                "## Sumber Data",
                f"- Live hosts: `{self.asset_files()['live']}`",
                f"- Interesting endpoints: `{self.endpoint_files()['interesting']}`",
                f"- Priority params: `{self.parameter_files()['priority_params']}`",
                "",
                "## Catatan",
                "- Verifikasi hanya pada aset yang masuk scope dan memiliki izin tertulis.",
                "- Pindahkan temuan tervalidasi ke folder findings sesuai severity.",
                "- Simpan screenshot, request, response, dan langkah reproduksi.",
            ]
        )
        self._safe_write(queue_file, content + "\n")
        result = StepResult(
            name="Manual Review Queue",
            files=[queue_file],
            notes=["Checklist manual review berhasil dibuat."],
        )
        return self._finalize_result("manual", result, started)

    def run_reporting(self) -> StepResult:
        started = time.perf_counter()
        self.ensure_structure()
        config_file = self.config.save()
        inventory_file = self.project_root / "reports" / "inventory.md"
        plan_file = self.project_root / "reports" / "execution-plan.md"
        report_file = self.project_root / "reports" / "summary.md"
        json_file = self.project_root / "reports" / "summary.json"
        assets = self.asset_files()
        endpoints = self.endpoint_files()
        params = self.parameter_files()

        summary = {
            "target": self.config.target,
            "scope": self.config.scope,
            "profile": self.config.profile,
            "project_root": str(self.project_root),
            "profile_settings": self.config.profile_settings,
            "counts": {
                "subdomains": len(self._read_lines(assets["subdomains"])),
                "live_hosts": len(self._read_lines(assets["live"])),
                "technologies": len(self._read_lines(assets["technologies"])),
                "dns_inventory": len(self._read_lines(assets["dns"])),
                "urls": len(self._read_lines(endpoints["urls"])),
                "interesting_urls": len(self._read_lines(endpoints["interesting"])),
                "javascript_urls": len(self._read_lines(endpoints["js"])),
                "api_urls": len(self._read_lines(endpoints["api"])),
                "query_urls": len(self._read_lines(params["query"])),
                "hidden_params": len(self._read_lines(params["hidden"])),
                "priority_params": len(self._read_lines(params["priority_params"])),
                "gf_xss": len(self._read_lines(params["gf_xss"])),
                "gf_sqli": len(self._read_lines(params["gf_sqli"])),
                "gf_ssrf": len(self._read_lines(params["gf_ssrf"])),
            },
            "tool_status": self.tools_status(),
        }

        markdown = [
            "# MaungAi Summary Report",
            "",
            f"- Target: {summary['target'] or 'belum diset'}",
            f"- Scope: {summary['scope'] or 'belum diset'}",
            f"- Profile: {summary['profile']}",
            f"- Project root: `{summary['project_root']}`",
            "",
            "## Counts",
        ]
        for key, value in summary["counts"].items():
            markdown.append(f"- {key}: {value}")
        markdown.extend(
            [
                "",
                "## Tool Status",
            ]
        )
        for key, value in summary["tool_status"].items():
            markdown.append(f"- {key}: {'ready' if value else 'missing'}")

        self._safe_write(report_file, "\n".join(markdown) + "\n")
        self._safe_write(json_file, json.dumps(summary, indent=2) + "\n")
        self._safe_write(inventory_file, self._build_inventory_markdown())
        self._safe_write(plan_file, self._build_execution_plan_markdown())
        result = StepResult(
            name="Reporting",
            files=[report_file, json_file, inventory_file, plan_file, config_file],
            notes=["Summary report, inventory, execution plan, dan config snapshot berhasil dibuat."],
        )
        return self._finalize_result("report", result, started)

    def run_full_pipeline(self) -> list[StepResult]:
        self.ensure_structure()
        return [
            self.run_asset_discovery(),
            self.run_live_host_validation(),
            self.run_endpoint_discovery(),
            self.run_parameter_analysis(),
            self.run_automated_checks(),
            self.run_manual_review_queue(),
            self.run_reporting(),
        ]

    def tools_status(self) -> dict[str, bool]:
        return {
            "subfinder": self._tool_exists("subfinder"),
            "httpx": self._tool_exists("httpx"),
            "katana": self._tool_exists("katana"),
            "gau": self._tool_exists("gau"),
            "waybackurls": self._tool_exists("waybackurls"),
            "gf": self._tool_exists("gf"),
            "uro": self._tool_exists("uro"),
            "nuclei": self._tool_exists("nuclei"),
        }

    def available_profiles(self) -> dict[str, str]:
        return {name: str(data.get("description", "")) for name, data in PIPELINE_PROFILES.items()}

    def _profile_list(self, key: str) -> list[str]:
        value = self.config.profile_settings.get(key, [])
        return [str(item) for item in value] if isinstance(value, list) else []

    def _tool_exists(self, executable: str) -> bool:
        return shutil.which(executable) is not None

    def _run_command(
        self,
        command: list[str],
        stdin_text: str | None = None,
        raw_name: str | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        if not self._tool_exists(command[0]):
            return None
        try:
            result = subprocess.run(
                command,
                input=stdin_text,
                text=True,
                capture_output=True,
                check=False,
                timeout=self.config.timeout_seconds,
            )
        except (OSError, subprocess.TimeoutExpired):
            return None

        if raw_name and self.config.save_logs:
            raw_file = self.raw_root / raw_name
            content = result.stdout
            if result.stderr.strip():
                content += "\n# stderr\n" + result.stderr
            self._safe_write(raw_file, content)
        return result

    def _finalize_result(self, step_id: str, result: StepResult, started: float) -> StepResult:
        result.duration_seconds = round(time.perf_counter() - started, 2)
        result.notes.append(f"Durasi: {result.duration_seconds}s")
        if self.config.save_logs:
            result.log_file = self.logs_root / f"{step_id}.md"
            self._safe_write(result.log_file, self._build_step_log(result))
            result.files.append(result.log_file)
        return result

    def _build_step_log(self, result: StepResult) -> str:
        lines = [f"# {result.name}", ""]
        lines.append(f"- success: {result.success}")
        lines.append(f"- duration_seconds: {result.duration_seconds}")
        if result.metrics:
            lines.append("")
            lines.append("## Metrics")
            for key, value in result.metrics.items():
                lines.append(f"- {key}: {value}")
        if result.commands:
            lines.append("")
            lines.append("## Commands")
            for command in result.commands:
                lines.append(f"- `{command}`")
        if result.notes:
            lines.append("")
            lines.append("## Notes")
            for note in result.notes:
                lines.append(f"- {note}")
        if result.warnings:
            lines.append("")
            lines.append("## Warnings")
            for warning in result.warnings:
                lines.append(f"- {warning}")
        if result.files:
            lines.append("")
            lines.append("## Files")
            for file in result.files:
                lines.append(f"- `{file}`")
        lines.append("")
        return "\n".join(lines)

    def _build_inventory_markdown(self) -> str:
        stats = self.quick_stats()
        return "\n".join(
            [
                "# Asset Inventory",
                "",
                f"- Target: {self.config.target or 'belum diset'}",
                f"- Scope: {self.config.scope or 'belum diset'}",
                f"- Profile: {self.config.profile}",
                "",
                "## Current Counts",
                *[f"- {key}: {value}" for key, value in stats.items()],
                "",
            ]
        )

    def _build_execution_plan_markdown(self) -> str:
        tool_status = self.tools_status()
        lines = [
            "# Execution Plan",
            "",
            f"- Profile: {self.config.profile}",
            f"- Description: {self.config.profile_settings.get('description', '')}",
            "",
            "## Steps",
        ]
        step_names = {
            "assets": "Subdomain discovery",
            "live": "Live host validation",
            "endpoints": "Endpoint discovery",
            "params": "Parameter analysis",
            "scan": "Automated checks",
            "manual": "Manual review queue",
            "report": "Reporting",
        }
        for step_id in STEP_ORDER:
            lines.append(f"- {step_id}: {step_names[step_id]}")
        lines.extend(["", "## Tool Status"])
        for name, ready in tool_status.items():
            lines.append(f"- {name}: {'ready' if ready else 'missing'}")
        lines.append("")
        return "\n".join(lines)

    def _display_command(self, command: Iterable[str]) -> str:
        return " ".join(command)

    def _safe_write(self, path: Path, content: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _write_lines(self, path: Path, lines: Iterable[str]) -> None:
        unique = self._clean_lines(lines)
        self._safe_write(path, "\n".join(unique) + ("\n" if unique else ""))

    def _read_lines(self, path: Path) -> list[str]:
        if not path.exists():
            return []
        return self._clean_lines(path.read_text(encoding="utf-8").splitlines())

    def _clean_lines(self, lines: Iterable[str]) -> list[str]:
        cleaned: list[str] = []
        seen: set[str] = set()
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line not in seen:
                seen.add(line)
                cleaned.append(line)
        return cleaned

    def _dedupe_urls(self, urls: Iterable[str]) -> list[str]:
        normalized: dict[str, str] = {}
        for url in urls:
            value = url.strip()
            if not value:
                continue
            parsed = urlparse(value)
            if not parsed.scheme or not parsed.netloc:
                continue
            pairs = parse_qsl(parsed.query, keep_blank_values=True)
            normalized_query = "&".join(f"{key}=" for key, _ in sorted(pairs))
            key = parsed._replace(query=normalized_query, fragment="").geturl()
            normalized[key] = value
        return sorted(normalized.values())

    def _interesting_urls(self, urls: Iterable[str]) -> list[str]:
        hints = (
            "login",
            "admin",
            "upload",
            "callback",
            "redirect",
            "debug",
            "config",
            "token",
            "export",
            "import",
            "graphql",
            "oauth",
        )
        return [url for url in urls if any(hint in url.lower() for hint in hints)]

    def _fallback_param_filter(self, urls: list[str], pattern_name: str) -> list[str]:
        keyword_map = {
            "xss": ("q=", "search=", "keyword=", "lang=", "redirect="),
            "sqli": ("id=", "user=", "account=", "order=", "sort="),
            "ssrf": ("url=", "uri=", "path=", "dest=", "callback="),
        }
        keywords = keyword_map.get(pattern_name, ())
        return [url for url in urls if any(keyword in url.lower() for keyword in keywords)]

    def _guess_dns_record(self, hostname: str) -> str:
        return f"{hostname} | unresolved | cek manual dengan dnsx/dig"
