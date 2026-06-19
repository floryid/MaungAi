import unittest
from pathlib import Path
import tempfile

from maungai.config import PipelineConfig, slugify_target


class ConfigTests(unittest.TestCase):
    def test_slugify_target(self) -> None:
        self.assertEqual(slugify_target("https://demo.example.com/test"), "https-demo.example.com-test")

    def test_config_save_and_load(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            workspace = Path(tmp_dir)
            config = PipelineConfig(
                target="example.com",
                scope="*.example.com",
                workspace_root=workspace,
                profile="fast",
                timeout_seconds=45,
            )
            config_path = workspace / "example.com" / "reports" / "config.json"
            config.save(config_path)

            loaded = PipelineConfig.load(config_path)
            self.assertEqual(loaded.target, "example.com")
            self.assertEqual(loaded.scope, "*.example.com")
            self.assertEqual(loaded.profile, "fast")
            self.assertEqual(loaded.timeout_seconds, 45)


if __name__ == "__main__":
    unittest.main()
