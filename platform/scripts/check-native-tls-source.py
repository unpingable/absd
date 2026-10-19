#!/usr/bin/env python3
"""Check the reviewed, deliberately narrow native TLS fixture source shape.

This lexical guard supplements review. It does not prove properties of arbitrary
Rust programs or scan upstream rustls. Its negative controls run with --self-test.
"""
from pathlib import Path
import argparse
import json
import re
import sys


class Refusal(ValueError):
    pass


def masked(source):
    """Blank comments and literals while preserving token positions/newlines."""
    out = list(source)
    i = 0
    while i < len(source):
        start = i
        if source.startswith('//', i):
            i = source.find('\n', i)
            if i < 0:
                i = len(source)
        elif source.startswith('/*', i):
            depth = 1
            i += 2
            while depth and i < len(source):
                if source.startswith('/*', i):
                    depth += 1
                    i += 2
                elif source.startswith('*/', i):
                    depth -= 1
                    i += 2
                else:
                    i += 1
            if depth:
                raise Refusal('unterminated block comment')
        else:
            raw = re.match(r'(?:br|cr|r)(#*)"', source[i:])
            if raw and (i == 0 or not (source[i - 1].isalnum() or source[i - 1] == '_')):
                terminator = '"' + raw.group(1)
                end = source.find(terminator, i + len(raw.group(0)))
                if end < 0:
                    raise Refusal('unterminated raw literal')
                i = end + len(terminator)
            elif source[i] == '"':
                i += 1
                while i < len(source) and source[i] != '"':
                    i += 2 if source[i] == '\\' else 1
                if i >= len(source):
                    raise Refusal('unterminated string literal')
                i += 1
            elif source[i] == "'":
                # Lifetimes stay visible. Only complete character literals mask.
                char = re.match(r"'(?:[^'\\\n]|\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.))'", source[i:])
                if char:
                    i += len(char.group(0))
                else:
                    i += 1
                    continue
            else:
                i += 1
                continue
        for n in range(start, min(i, len(source))):
            if out[n] != '\n':
                out[n] = ' '
    return ''.join(out)


FORBIDDEN_WORDS = {
    'dangerous', 'dangerous_extract_secrets', 'dangerous_into_kernel_connection',
    'KeyLogFile',
    'with_custom_certificate_verifier', 'set_certificate_verifier', 'key_log',
    'include', 'include_str', 'macro_rules',
}
ALLOWED_MACROS = {
    'vec', 'format', 'println', 'eprintln', 'print', 'eprint', 'panic',
    'assert', 'assert_eq', 'assert_ne', 'debug_assert', 'debug_assert_eq',
    'debug_assert_ne', 'matches', 'include_bytes', 'env', 'option_env',
    'unreachable', 'todo', 'write', 'writeln', 'cfg', 'asm',
}


def inspect_sources(sources):
    if not sources:
        raise Refusal('no first-party TLS Rust source')
    checked = {}
    for path, source in sources.items():
        code = masked(source)
        words = set(re.findall(r'\b[A-Za-z_][A-Za-z_0-9]*\b', code))
        refused = sorted(words & FORBIDDEN_WORDS)
        if refused:
            raise Refusal(path + ': refused API or hidden source: ' + ', '.join(refused))
        if re.search(r'\bimpl\b[^{;]*\b(?:ServerCertVerifier|KeyLog)\b', code):
            raise Refusal(path + ': custom certificate verifier or key log implementation')
        if re.search(r'#\s*\[\s*path\s*=', code) or re.search(
                r'#\s*\[\s*cfg_attr\s*\([^\]]*\bpath\s*=', code):
            raise Refusal(path + ': external module path')
        for field in ['enable_early_data', 'enable_secret_extraction']:
            for match in re.finditer(r'\b' + field + r'\s*[:=]\s*([^;,}\n]+)', code):
                if match.group(1).strip() != 'false':
                    raise Refusal(path + ': ' + field + ' must stay explicitly false')
        for match in re.finditer(r'\b([A-Za-z_][A-Za-z_0-9]*)\s*!\s*[({\[]', code):
            if match.group(1) not in ALLOWED_MACROS:
                raise Refusal(path + ': unreviewed macro ' + match.group(1))
        # A Rust alias could obscure the configuration types from this guard.
        if re.search(r'\buse\s+rustls\s+as\b', code) or re.search(
                r'\buse\s+rustls\b[^;]*\bself\s+as\s+\w+', code) or re.search(
                r'\b(?:ClientConfig|Resumption|ServerCertVerifier|KeyLog)\s+as\s+\w+', code) or re.search(
                r'\btype\s+\w+\s*=\s*(?:rustls::)?ClientConfig\b', code):
            raise Refusal(path + ': aliased TLS configuration requires review')
        checked[path] = code
    engine = checked.get('tls/src/engine.rs')
    if engine is None:
        raise Refusal('canonical tls/src/engine.rs configuration is missing')
    required = {
        'disabled resumption': r'\bresumption\s*=\s*(?:rustls::client::)?Resumption\s*::\s*disabled\s*\(\s*\)',
        'standard root verifier': r'\.\s*with_root_certificates\s*\(',
        'TLS 1.3 only selection': r'\.\s*with_protocol_versions\s*\(\s*&\s*\[\s*&\s*(?:rustls::version::)?TLS13\s*\]\s*\)',
        'no client certificate': r'\.\s*with_no_client_auth\s*\(\s*\)',
    }
    for name, pattern in required.items():
        if len(re.findall(pattern, engine)) != 1:
            raise Refusal('canonical configuration must contain exactly one ' + name)
    if sum(len(re.findall(r'\bresumption\b', code)) for code in checked.values()) != 1:
        raise Refusal('resumption may occur only in its one canonical disabled assignment')
    if re.search(r'\bTLS12\b', engine):
        raise Refusal('TLS 1.2 configuration is outside the fixture')
    return {'disposition': 'PASS', 'files': sorted(sources),
            'limit': 'Lexical source-shape guard plus review; not a proof for arbitrary Rust.'}


def self_test():
    config = '''fn config() {
        let mut config = ClientConfig::builder_with_details(provider, time)
            .with_protocol_versions(&[&TLS13]).unwrap()
            .with_root_certificates(roots).with_no_client_auth();
        config.resumption = Resumption::disabled();
    }'''
    inspect_sources({'tls/src/engine.rs': config})
    cases = []
    for word in sorted(FORBIDDEN_WORDS):
        cases.append(('word:' + word, config + '\nfn bad() { ' + word + '(); }'))
    for field in ['enable_early_data', 'enable_secret_extraction']:
        for value in ['true', 'value', 'compute()']:
            cases.append((field + ':' + value, config + f'\nfn bad() {{ config.{field} = {value}; }}'))
    cases += [
        ('generated macro', config + '\nconfigure_tls!();'),
        ('module path', config + '\n#[path="other.rs"] mod hidden;'),
        ('conditional module path', config + '\n#[cfg_attr(target_os="absd",path="/outside.rs")] mod hidden;'),
        ('type alias', config + '\ntype Hidden = rustls::ClientConfig;'),
        ('use alias', config + '\nuse rustls::ClientConfig as Hidden;'),
        ('resumption missing', config.replace('config.resumption = Resumption::disabled();', '')),
        ('resumption overridden', config + '\nfn bad() { config.resumption = Resumption::in_memory_sessions(8); }'),
        ('resumption replaced', config + '\nfn bad() { std::mem::replace(&mut config.resumption, previous); }'),
        ('root verifier missing', config.replace('.with_root_certificates(roots)', '')),
        ('TLS version missing', config.replace('TLS13', 'VERSION')),
        ('TLS 1.2', config + '\nconst OTHER: Version = TLS12;'),
        ('custom verifier', config + '\nimpl ServerCertVerifier for Other {}'),
        ('custom generic verifier', config + '\nimpl<T> ServerCertVerifier for Other<T> {}'),
        ('custom key log', config + '\nimpl KeyLog for Other {}'),
        ('unterminated comment', config + '\n/*'),
        ('unterminated string', config + '\nlet x = "unfinished'),
        ('unterminated raw string', config + '\nlet x = r##"unfinished'),
    ]
    for name, source in cases:
        try:
            inspect_sources({'tls/src/engine.rs': source})
        except Refusal:
            continue
        raise Refusal('negative control passed: ' + name)
    harmless = config + '''
        // dangerous() and KeyLogFile are comments, not configuration.
        /* nested /* dangerous */ comment */
        const EXAMPLE: &str = r###"dangerous() with_custom_certificate_verifier"###;
        const ORDINARY: &str = "KeyLogFile \\\" example";
        use rustls::client::danger::ServerCertVerifier;
        use rustls::{CertificateError as C, Error as E};
        use absd_net::datagram::{self as d};
        fn life<'a>(value: &'a str) { let c = '\\n'; }
    '''
    inspect_sources({'tls/src/engine.rs': harmless})
    return {'disposition': 'PASS', 'negative_controls': len(cases),
            'positive_controls': 2, 'limit': 'Finite deterministic source-gate controls only.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument('--self-test', action='store_true')
    args = parser.parse_args()
    if sys.flags.optimize or bool(__import__('os').environ.get('PYTHONOPTIMIZE')):
        raise Refusal('optimized Python is refused')
    if args.self_test:
        result = self_test()
    else:
        source_root = args.root / 'tls' / 'src'
        files = sorted(source_root.rglob('*.rs'))
        if any(path.is_symlink() for path in files) or (args.root / 'tls' / 'build.rs').exists():
            raise Refusal('generated build source or symlink requires review')
        result = inspect_sources({str(p.relative_to(args.root)): p.read_text() for p in files})
    print(json.dumps(result, sort_keys=True))


if __name__ == '__main__':
    try:
        main()
    except (Refusal, OSError, UnicodeError) as error:
        print('native TLS source gate: ' + str(error), file=sys.stderr)
        sys.exit(1)
