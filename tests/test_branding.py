import json
from pathlib import Path
import sqlite3
import sys
import types
import unittest
from unittest.mock import patch

from tests.test_panel_performance import load_backend


ROOT = Path(__file__).resolve().parents[1]


class LogQuery:
    def __init__(self, connection):
        self.connection = connection

    def where(self, expression, parameters):
        self.expression, self.parameters = expression, parameters
        return self

    def count(self):
        return self.connection.execute(
            'SELECT COUNT(*) FROM logs WHERE ' + self.expression, self.parameters
        ).fetchone()[0]

    def order(self, expression):
        self.order_by = expression
        return self

    def limit(self, expression):
        self.offset, self.rows = map(int, expression.split(','))
        return self

    def field(self, expression):
        self.fields = expression
        return self

    def select(self):
        cursor = self.connection.execute(
            'SELECT ' + self.fields + ' FROM logs WHERE ' + self.expression
            + ' ORDER BY ' + self.order_by + ' LIMIT ? OFFSET ?',
            tuple(self.parameters) + (self.rows, self.offset),
        )
        return [dict(zip([column[0] for column in cursor.description], row)) for row in cursor]


class BrandingTest(unittest.TestCase):
    def test_plugin_metadata_uses_new_brand_without_changing_identity_or_attribution(self):
        info = json.loads((ROOT / 'info.json').read_text(encoding='utf-8'))
        self.assertEqual(info['title'], 'aapanel GPT Firewall')
        self.assertEqual(info['ps'], '网站应用防火墙 · 社区兼容升级版')
        self.assertEqual(info['name'], 'free_waf')
        self.assertEqual(info['checks'], '/www/server/panel/plugin/free_waf')
        self.assertEqual(info['shell'], 'free_waf.sh')
        self.assertEqual(info['author'], '民国三年一场雨')
        self.assertEqual(info['versions'], '0.1.6')

    def test_management_heading_and_export_names_use_new_brand(self):
        body = (ROOT / 'index.html').read_text(encoding='utf-8')
        self.assertTrue('<strong>aapanel GPT Firewall</strong>' in body, 'workspace header uses old branding')
        self.assertIn('<h3>安全总览</h3>', body)
        self.assertTrue("'gpt_firewall_rule_bundle.json'" in body, 'rule export uses old branding')
        self.assertTrue("'gpt_firewall_blockade_records.json'" in body, 'ban export uses old branding')
        self.assertNotIn('当前 free_waf 基础版', body)
        self.assertIn("plugin_name:'free_waf'", body)

    def test_public_block_templates_do_not_disclose_new_or_old_brand(self):
        templates = list((ROOT / 'html').glob('*.html'))
        self.assertTrue(templates)
        for path in templates:
            with self.subTest(template=path.name):
                body = path.read_text(encoding='utf-8').lower()
                for brand in ('gpt firewall', 'aapanel', 'nginx free firewall', 'free edition'):
                    self.assertNotIn(brand, body)

    def setUp(self):
        self.connection = sqlite3.connect(':memory:')
        self.addCleanup(self.connection.close)
        self.connection.execute('CREATE TABLE logs (id INTEGER PRIMARY KEY, type TEXT, log TEXT, addtime TEXT)')

        def write_log(category, message):
            self.connection.execute('INSERT INTO logs(type,log,addtime) VALUES (?,?,?)',
                                    (category, message, '2026-10-22 12:00:00'))

        self.public = types.SimpleNamespace(
            M=lambda table: LogQuery(self.connection), WriteLog=write_log,
        )
        self.backend = load_backend(self.public)

    def test_new_audit_entries_use_new_category(self):
        self.backend._free_waf_main__write_log('修改配置')
        self.assertEqual(self.connection.execute('SELECT type,log FROM logs').fetchone(),
                         ('GPT Firewall', '修改配置'))

    def test_paginated_audit_reads_both_categories_and_excludes_other_products(self):
        for index in range(13):
            self.public.WriteLog('Nginx free firewall' if index % 2 else 'GPT Firewall', str(index))
        self.public.WriteLog('unrelated', 'not ours')
        counts = []

        class Page:
            def GetPage(self, info, style):
                counts.append(info['count'])
                self.SHIFT, self.ROW = (info['p'] - 1) * info['row'], info['row']
                return str(info['count'])

        class Args(dict):
            __getattr__ = dict.__getitem__

        module = types.ModuleType('page')
        module.Page = Page
        with patch.dict(sys.modules, {'page': module}):
            first = self.backend.get_gl_logs(Args(p=1, tojs='test'))
            second = self.backend.get_gl_logs(Args(p=2, tojs='test'))
        self.assertEqual(counts, [13, 13])
        self.assertEqual(len(first['data']), 12)
        self.assertEqual(len(second['data']), 1)
        self.assertEqual([row['log'] for row in first['data'] + second['data']],
                         [str(index) for index in reversed(range(13))])


if __name__ == '__main__':
    unittest.main()
