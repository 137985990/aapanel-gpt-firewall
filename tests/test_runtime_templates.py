import unittest
from pathlib import Path


class RuntimeTemplateTest(unittest.TestCase):
    def setUp(self):
        runtime_dir = Path(__file__).resolve().parents[1] / "html"
        self.templates = sorted(runtime_dir.glob("*.html"))

    def test_block_pages_are_neutral_and_chinese(self):
        self.assertTrue(self.templates)
        forbidden = [
            "aapanel",
            "website firewall",
            "free edition",
            "forum.aapanel.com",
        ]
        for path in self.templates:
            with self.subTest(template=path.name):
                body = path.read_text(encoding="utf-8", errors="replace")
                lower_body = body.lower()
                for text in forbidden:
                    self.assertNotIn(text, lower_body)
                self.assertIn("请求已被拒绝", body)
                self.assertIn("联系网站管理员", body)


if __name__ == "__main__":
    unittest.main()
