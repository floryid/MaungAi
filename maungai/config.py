from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
import re


DEFAULT_TIMEOUT = 120

PIPELINE_PROFILES: dict[str, dict[str, object]] = {
    "fast": {
        "description": "Recon cepat untuk triage awal dengan request hemat.",
        "crawler_depth": 2,
        "katana_extra_args": ["-js-crawl"],
        "httpx_extra_args": ["-follow-host-redirects"],
        "nuclei_extra_args": ["-rl", "25", "-c", "25"],
        "use_historical_urls": True,
    },
    "balanced": {
        "description": "Preset default untuk workflow harian bug hunter.",
        "crawler_depth": 4,
        "katana_extra_args": ["-js-crawl", "-known-files", "all"],
        "httpx_extra_args": ["-follow-redirects", "-title"],
        "nuclei_extra_args": ["-rl", "50", "-c", "50"],
        "use_historical_urls": True,
    },
    "deep": {
        "description": "Recon lebih dalam untuk scope sempit dan audit resmi.",
        "crawler_depth": 6,
        "katana_extra_args": ["-js-crawl", "-known-files", "all", "-xhr-extraction"],
        "httpx_extra_args": ["-follow-redirects", "-title", "-server", "-ip"],
        "nuclei_extra_args": ["-rl", "80", "-c", "80"],
        "use_historical_urls": True,
    },
}


def slugify_target(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9._-]+", "-", value.strip())
    cleaned = cleaned.strip("-._")
    return cleaned or "unknown-target"


@dataclass
class PipelineConfig:
    target: str = ""
    scope: str = ""
    workspace_root: Path = Path("project")
    profile: str = "balanced"
    timeout_seconds: int = DEFAULT_TIMEOUT
    save_logs: bool = True
    allow_historical_urls: bool = True

    @property
    def is_ready(self) -> bool:
        return bool(self.target.strip())

    @property
    def target_slug(self) -> str:
        return slugify_target(self.target)

    @property
    def project_root(self) -> Path:
        return self.workspace_root / self.target_slug

    @property
    def profile_settings(self) -> dict[str, object]:
        return PIPELINE_PROFILES.get(self.profile, PIPELINE_PROFILES["balanced"])

    @property
    def config_file(self) -> Path:
        return self.project_root / "reports" / "maungai-config.json"

    def set_target(self, target: str, scope: str | None = None) -> None:
        self.target = target.strip()
        if scope is not None:
            self.scope = scope.strip()

    def set_profile(self, profile: str) -> None:
        selected = profile.strip().lower()
        if selected in PIPELINE_PROFILES:
            self.profile = selected

    def validate(self) -> list[str]:
        warnings: list[str] = []
        if not self.target.strip():
            warnings.append("Target masih kosong.")
        if self.scope and self.target and self.target not in self.scope and "*" not in self.scope:
            warnings.append("Scope tidak terlihat mencakup target utama.")
        if self.timeout_seconds < 10:
            warnings.append("Timeout terlalu rendah, hasil bisa tidak akurat.")
        return warnings

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        data["workspace_root"] = str(self.workspace_root)
        data["profile_description"] = self.profile_settings.get("description", "")
        return data

    def save(self, file_path: Path | None = None) -> Path:
        target_file = file_path or self.config_file
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_text(json.dumps(self.to_dict(), indent=2) + "\n", encoding="utf-8")
        return target_file

    @classmethod
    def load(cls, file_path: Path) -> "PipelineConfig":
        data = json.loads(file_path.read_text(encoding="utf-8"))
        return cls(
            target=str(data.get("target", "")),
            scope=str(data.get("scope", "")),
            workspace_root=Path(str(data.get("workspace_root", "project"))),
            profile=str(data.get("profile", "balanced")),
            timeout_seconds=int(data.get("timeout_seconds", DEFAULT_TIMEOUT)),
            save_logs=bool(data.get("save_logs", True)),
            allow_historical_urls=bool(data.get("allow_historical_urls", True)),
        )
