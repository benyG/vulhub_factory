import json, tomllib, pathlib
repo_root = pathlib.Path('.')
with open(repo_root / 'environments.toml', 'rb') as f:
    data = tomllib.load(f)
envs = data.get('environment', [])
priority = [
    ('rce', 'rce'),
    ('remote code execution', 'rce'),
    ('deserialization', 'deserialization'),
    ('sql injection', 'sqli'),
    ('ssrf', 'ssrf'),
    ('ssrf', 'ssrf'),
    ('file inclusion', 'lfi'),
    ('local file inclusion', 'lfi'),
    ('path traversal', 'path_traversal'),
    ('directory traversal', 'path_traversal'),
    ('xxe', 'xxe'),
    ('ssti', 'ssti'),
    ('auth bypass', 'auth_bypass'),
    ('authentication bypass', 'auth_bypass'),
    ('command injection', 'command_injection'),
    ('environment injection', 'command_injection'),
    ('expression injection', 'command_injection'),
    ('file upload', 'command_injection'),
    ('info disclosure', 'unauth_access'),
    ('dos', 'unauth_access'),
]
allowed = ["rce","deserialization","sqli","ssrf","lfi","xxe","auth_bypass","command_injection","ssti","path_traversal","unauth_access"]

def map_category(tags):
    for tag in tags:
        tag_norm = tag.lower()
        for needle, cat in priority:
            if needle in tag_norm:
                return cat
    return 'unauth_access'

def affected_version(env):
    dockerfile = env.get('dockerfile') or {}
    if isinstance(dockerfile, dict):
        for key, value in dockerfile.items():
            if isinstance(key, str) and ':' in key:
                return key.split(':', 1)[1]
            if isinstance(value, str):
                if '/' in value:
                    return value.split('/')[-1]
                return value
    return ''

categories = {cat: [] for cat in allowed}
for env in envs:
    tags = env.get('tags', []) or []
    cat = map_category(tags)
    cve_list = env.get('cve') or []
    cve_id = cve_list[0] if cve_list else env.get('name', '')
    version = affected_version(env)
    entry = {
        'cve_id': cve_id,
        'software': env.get('app'),
        'affected_version': version or '',
        'category': cat,
        'cvss_score': 0.0,
        'difficulty': 'medium',
        'vulhub_path': env.get('path'),
        'flag_placement': None,
        'flag_path': None,
        'solve_summary': None,
        'vpn_required': True,
    }
    categories.setdefault(cat, []).append(entry)
metadata = {
    'source': 'Vulhub GitHub Repository (https://github.com/vulhub/vulhub)',
    'generated': '2026-03-26',
    'total_entries': len(envs),
    'criteria': 'CVSS >= 7.0, clear exploitation steps, CTF-suitable, docker-compose available',
}
output = {
    'metadata': metadata,
    'categories': categories,
}
with open(repo_root / 'vulhub_cve_list.json', 'w', encoding='utf-8') as f:
    json.dump(output, f, ensure_ascii=False, indent=2)
