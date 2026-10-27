"""Build an allowlisted source snapshot and the offline compatibility upgrade ZIP."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile


VERSION = '0.1.11'
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
    'docs/images/statistics.png',
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
    'tests/test_repeat_ban_bulk.py', 'tests/test_repeat_ban_bulk_ui.js',
    'tests/test_risk_advice_store.py', 'tests/test_risk_advice_backend.py',
    'tests/test_risk_advice_runtime.py', 'tests/test_risk_advice_ui.js',
    'tests/test_review_backend_regressions.py', 'tests/test_review_ui_regressions.js',
    'tests/test_review_installer_regressions.py', 'tests/test_review_runtime_regressions.py',
    'tests/test_review_runtime_regressions.lua',
    'tests/test_forum_regressions.py', 'tests/test_post_forwarding_runtime.py',
    'tests/test_cc_scope.py', 'tests/test_cc_config_validation.py',
    'tests/test_report_backend_regressions.py', 'tests/test_report_pagination_ui.js',
)
SECRET_PATTERNS = (
    r'(?m)^[ \t>]*-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----',
    r'\bgh[pousr]_[A-Za-z0-9]{30,}\b',
    r'\bgithub_pat_[A-Za-z0-9_]{40,}\b',
    r'\bsk-(?:proj-)?[A-Za-z0-9_-]{40,}\b',
)
PUBLIC_PATH_PATTERNS = (
    r'(?i)\b[a-z]:/+Users/+[^<>{}/\r\n\s\'"]+',
    r'(?i)(?<![\w:/])/{2,}[^/<>{}\s\'"]+/+(?:Users|Profiles)/+[^/<>{}\s\'"]+',
    r'(?<!\w)/+(?:home|Users)/+[^/<>{}\s\'"]+',
    # Generic root backup/vendor paths are public; named private profiles are not.
    r'(?i)(?<!\w)/+root/+(?:\.ssh|\.codex|Desktop|Documents)(?=/|$|[\s\'"`<>])',
)


def load_private_terms(path):
    try:
        path = Path(path)
        if path.is_symlink() or not path.is_file():
            raise ValueError
        with path.open('rb') as stream:
            data = stream.read(65537)
        if len(data) > 65536:
            raise ValueError
        terms = json.loads(data.decode('utf-8-sig'))
        if (type(terms) is not list or not 1 <= len(terms) <= 256 or any(
                type(term) is not str or not 1 <= len(term) <= 256
                or term != term.strip() or any(ord(char) < 32 or ord(char) == 127 for char in term)
                for term in terms)):
            raise ValueError
        return terms
    except (OSError, ValueError, UnicodeError):
        raise ValueError('私有敏感词清单不可读、格式不正确或超过上限。') from None


def validate_public_text(text, label, private_terms=(), public_document=False):
    if any(re.search(pattern, text) for pattern in SECRET_PATTERNS):
        raise ValueError('检测到疑似凭据，已停止发布校验：' + label)
    path_text = text.replace('\\', '/')
    if any(re.search(pattern, path_text) for pattern in PUBLIC_PATH_PATTERNS):
        raise ValueError('检测到本地用户目录，已停止发布校验：' + label)
    for term in private_terms:
        pattern = r'(?<![A-Za-z0-9])' + re.escape(term) + r'(?![A-Za-z0-9])'
        if re.search(pattern, text, flags=re.IGNORECASE):
            raise ValueError('检测到私有环境信息，已停止发布校验：' + label)


def build(root, output, release_notes=None, private_terms=()):
    root, output = Path(root).resolve(), Path(output).resolve()
    if output.exists():
        raise ValueError('输出目录已存在，请选择新的目录，避免覆盖已有文件。')
    if release_notes is not None:
        if not private_terms:
            raise ValueError('校验更新说明必须提供非空私有敏感词清单。')
        validate_public_text(release_notes, '更新说明', private_terms, public_document=True)
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
        validate_public_text(text, name, private_terms, public_document=name.endswith('.md'))
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


def main():
    parser = argparse.ArgumentParser(description='构建纯中文离线兼容升级包，不读取线上配置。')
    parser.add_argument('--root', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--check-notes', type=Path, help='同时校验单独编写的公开更新说明；不传输出目录时只校验。')
    parser.add_argument('--private-terms', type=Path, help='仓库外的本地私有敏感词 JSON 清单，不复制到发布内容。')
    args = parser.parse_args()
    if not args.output and not args.check_notes:
        parser.error('请指定输出目录或要校验的更新说明。')
    if args.check_notes and not args.private_terms:
        parser.error('校验更新说明时必须提供仓库外的私有敏感词清单。')
    try:
        args.root = (args.root if args.root is not None else Path(__file__).resolve().parents[1]).resolve()
        if args.private_terms and args.private_terms.resolve().is_relative_to(args.root):
            raise ValueError('私有敏感词清单必须保存在仓库外，不加入源码或发布包。')
        terms = load_private_terms(args.private_terms) if args.private_terms else []
        notes = None
        if args.check_notes:
            if args.check_notes.is_symlink() or not args.check_notes.is_file():
                raise ValueError('更新说明必须是普通文件。')
            with args.check_notes.open('rb') as stream:
                data = stream.read(1024 * 1024 + 1)
            if len(data) > 1024 * 1024:
                raise ValueError('更新说明超过校验上限。')
            notes = data.decode('utf-8-sig')
            validate_public_text(notes, '更新说明', terms, public_document=True)
        result = build(args.root, args.output, notes, terms) if args.output else dict(notes_checked=True)
        if notes is not None:
            result['notes_checked'] = True
        print(json.dumps(result, ensure_ascii=False))
    except (OSError, UnicodeError, RuntimeError):
        parser.error('无法读取发布输入；未公开原始路径或文件内容。')
    except ValueError as error:
        parser.error(str(error))


if __name__ == '__main__':
    main()
