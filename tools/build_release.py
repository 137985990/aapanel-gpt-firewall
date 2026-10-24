"""Build an allowlisted source snapshot and the offline compatibility upgrade ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


VERSION = '0.1.8'
PLUGIN_FILES = (
    'info.json', 'install.sh', 'free_waf_main.py', 'index.html',
    'init.lua', 'ban_store.py', 'report_store.py', 'website_statistics.py', 'update_service.py',
    'html/get.html', 'html/post.html', 'html/cookie.html',
    'html/user_agent.html', 'html/other.html',
    'README.md', 'NOTICE.md', 'CHANGELOG.md', 'SECURITY.md', 'docs/UPGRADE.md', 'docs/UPDATES.md',
    'docs/images/overview.png',
)
SOURCE_FILES = PLUGIN_FILES + (
    '.gitignore', '.gitattributes', 'AGENTS.md', 'tools/ci-template.yml',
    'docs/images/policies.png', 'docs/images/statistics.png',
    'docs/images/task-manager.png',
    'tools/build_release.py', 'tools/check.py',
    'tools/audit_registration_state.lua', 'tools/audit_rule_identity.lua', 'tools/audit_runtime_routes.lua',
    'tools/audit_endpoint_policy.lua', 'tools/audit_repeat_ban.lua',
    'tests/__init__.py', 'tests/test_attack_geography.py',
    'tests/test_visitor_geography.py', 'tests/test_visitor_geography_ui.js',
    'tests/test_backend_policy.py', 'tests/test_ban_store.py', 'tests/test_branding.py',
    'tests/test_frontend_ui_contract.py', 'tests/test_lua_policy.py',
    'tests/test_panel_performance.py', 'tests/test_report_store.py',
    'tests/test_runtime_templates.py', 'tests/test_unban_results.py',
    'tests/test_release_privacy.py', 'tests/test_release_package.py',
    'tests/test_offline_installer.py', 'tests/test_lua_state_regressions.py',
    'tests/test_attack_charts.js', 'tests/test_frontend_performance.js',
    'tests/test_website_statistics.py', 'tests/test_update_service.py', 'tests/test_v011_integration.py',
    'tests/test_statistics_v011.js', 'tests/test_plugin_update_ui.js',
    'tests/test_endpoint_policy.py', 'tests/test_security_boundary.py', 'tests/test_endpoint_policy_ui.js',
    'tests/test_runtime_status.py', 'tests/test_console_ui.js',
    'tests/test_integration_repair.py', 'tests/test_integration_runtime.py', 'tests/test_integration_probe.py',
    'tests/test_task_manager.py', 'tests/test_task_manager_ui.js',
    'tests/test_repeat_ban_policy.py', 'tests/test_repeat_ban_runtime.py', 'tests/test_repeat_ban_ui.js',
    'tests/test_review_backend_regressions.py', 'tests/test_review_ui_regressions.js',
    'tests/test_review_installer_regressions.py', 'tests/test_review_runtime_regressions.py',
    'tests/test_review_runtime_regressions.lua',
)
SECRET_PATTERNS = (
    r'(?m)^-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    r'\bgithub_pat_[A-Za-z0-9_]{40,}\b',
    r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
)


def build(root, output):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('输出目录已存在，请选择新的目录，避免覆盖已有文件。')
    metadata = json.loads((root / 'info.json').read_text(encoding='utf-8'))
    if metadata.get('versions') != VERSION or metadata.get('name') != 'free_waf':
        raise ValueError('发布版本或插件内部标识不匹配。')
    payloads = {}
    for name in SOURCE_FILES:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('不允许发布符号链接或工作区外的文件：' + name)
        data = path.read_bytes()
        if name.startswith('docs/images/') and name.endswith('.png'):
            if not data.startswith(b'\x89PNG\r\n\x1a\n') or len(data) > 2 * 1024 * 1024:
                raise ValueError('示例截图格式或大小不正确。')
            payloads[name] = data
            continue
        # Normalize only text line endings so archives are reproducible across OSes.
        text = data.decode('utf-8').replace('\r\n', '\n')
        if any(re.search(pattern, text) for pattern in SECRET_PATTERNS):
            raise ValueError('文件包含疑似凭据，已停止打包：' + name)
        payloads[name] = text.encode('utf-8')
    source = output / 'source'
    source.mkdir(parents=True)
    for name, data in payloads.items():
        target = source / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
    archive = output / ('aapanel-gpt-firewall-' + VERSION + '-upgrade.zip')
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as package:
        for name in sorted(PLUGIN_FILES):
            info = zipfile.ZipInfo('free_waf/' + name, date_time=(2026, 10, 23, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (0o100755 if name == 'install.sh' else 0o100644) << 16
            package.writestr(info, payloads[name])
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
    return dict(archive=str(archive), source=str(source), sha256=digest, version=VERSION)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='构建纯中文离线兼容升级包，不读取线上配置。')
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(build(args.root, args.output), ensure_ascii=False))
