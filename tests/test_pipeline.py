import unittest
from pathlib import Path

from maungai.config import PipelineConfig
from maungai.pipeline import PipelineRunner


class PipelineTests(unittest.TestCase):
    def test_dedupe_urls(self) -> None:
        runner = PipelineRunner(PipelineConfig(target="example.com", workspace_root=Path("tmp-tests")))
        urls = [
            "https://example.com/search?q=one&id=1",
            "https://example.com/search?q=two&id=2",
            "https://example.com/login?redirect=/home",
            "not-a-url",
        ]
        result = runner._dedupe_urls(urls)
        self.assertEqual(len(result), 2)

    def test_interesting_urls_filter(self) -> None:
        runner = PipelineRunner(PipelineConfig(target="example.com", workspace_root=Path("tmp-tests")))
        urls = [
            "https://example.com/login",
            "https://example.com/static/app.js",
            "https://example.com/api/users",
        ]
        result = runner._interesting_urls(urls)
        self.assertEqual(result, ["https://example.com/login"])


if __name__ == "__main__":
    unittest.main()
