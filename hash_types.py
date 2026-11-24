"""Report-only format identification; never changes password boundaries.

Signatures describe common encodings, not proof of the underlying algorithm.
Raw digest length alone is deliberately insufficient. Extend SIGNATURES with
specific complete representations instead of broad prefix/length guesses.
"""
import re
from potfile_parser import STRUCTURES

UNKNOWN = 'Unknown / ambiguous'
PLAINTEXT = 'Plaintext (no hash)'
HEX = rb'[0-9a-fA-F]'
B64 = rb'[A-Za-z0-9+/=]+'
CRYPT64 = rb'[./A-Za-z0-9]'

SIGNATURES = tuple((re.compile(pattern), name) for pattern, name in (
    *((pattern, name) for pattern, name in zip(STRUCTURES, (
        'Kerberos TGS', 'Kerberos TGS', 'Kerberos AS-REP', 'NetNTLMv2', 'NetNTLMv1'))),
    (rb'\$NT\$' + HEX + rb'{32}', 'NTLM'),
    (rb'\$LM\$(?:' + HEX + rb'{16}|' + HEX + rb'{32})', 'LM (LanMan)'),
    (rb'\$2[abxy]\$\d{2}\$' + CRYPT64 + rb'{53}', 'bcrypt'),
    (rb'\$1\$' + CRYPT64 + rb'{1,8}\$' + CRYPT64 + rb'{22}', 'md5crypt'),
    (rb'\$apr1\$' + CRYPT64 + rb'{1,8}\$' + CRYPT64 + rb'{22}', 'Apache MD5 (apr1)'),
    (rb'\$5\$(?:rounds=[1-9]\d*\$)?' + CRYPT64 + rb'{1,16}\$' + CRYPT64 + rb'{43}', 'sha256crypt'),
    (rb'\$6\$(?:rounds=[1-9]\d*\$)?' + CRYPT64 + rb'{1,16}\$' + CRYPT64 + rb'{86}', 'sha512crypt'),
    (rb'\$y\$' + CRYPT64 + rb'+\$' + CRYPT64 + rb'+\$' + CRYPT64 + rb'+', 'yescrypt'),
    (rb'\$7\$' + CRYPT64 + rb'+\$' + CRYPT64 + rb'+', 'scrypt (crypt)'),
    (rb'SCRYPT:[1-9]\d*:[1-9]\d*:[1-9]\d*:' + B64 + rb':' + B64, 'scrypt'),
    *((rb'\$argon2' + variant + rb'\$(?:v=\d+\$)?m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+',
       'Argon2' + variant.decode()) for variant in (b'i', b'd', b'id')),
    (rb'\$[PH]\$' + CRYPT64 + rb'{31}', 'phpass'),
    (rb'\$DCC2\$[1-9]\d*#[^#\r\n]+#' + HEX + rb'{32}', 'DCC2 (MS Cache v2)'),
    (rb'0x0100' + HEX + rb'{48}', 'MSSQL (2005)'),
    (rb'0x0100' + HEX + rb'{88}', 'MSSQL (2000)'),
    (rb'0x0200' + HEX + rb'{136}', 'MSSQL (2012+)'),
    (rb'\*' + HEX + rb'{40}', 'MySQL (4.1+)'),
    (rb'\{SHA\}' + B64, 'LDAP SHA-1'),
    (rb'\{SSHA\}' + B64, 'LDAP salted SHA-1'),
    *((b'sha' + bits + rb':[1-9]\d*:' + B64 + rb':' + B64,
       'PBKDF2-HMAC-SHA' + bits.decode()) for bits in (b'1', b'256', b'512')),
    *((rb'\$pbkdf2-sha' + bits + rb'\$[1-9]\d*\$[./A-Za-z0-9]+\$[./A-Za-z0-9]+',
       'PBKDF2-HMAC-SHA' + bits.decode()) for bits in (b'256', b'512')),
    (rb'pbkdf2_sha256\$[1-9]\d*\$[^$\r\n]+\$' + B64, 'Django PBKDF2-SHA256'),
))


def normalize_hint(hint):
    """Allow arbitrary consultant-declared types, with a few canonical aliases."""
    hint = hint.strip()
    if not hint or len(hint) > 120 or any(ord(char) < 32 or ord(char) == 127 for char in hint):
        raise ValueError('Hash type must be 1–120 printable characters')
    return {'auto': 'auto', 'ntlm': 'NTLM', 'lm': 'LM (LanMan)',
            'lanman': 'LM (LanMan)', 'md5': 'MD5', 'sha1': 'SHA-1',
            'sha256': 'SHA-256', 'sha512': 'SHA-512'}.get(hint.lower(), hint)


def identify_hash_type(hash_part, hint='auto'):
    """Return (type, basis), honoring a hint only for unidentified encodings."""
    hint = normalize_hint(hint)
    for pattern, name in SIGNATURES:
        if pattern.fullmatch(hash_part):
            return name, 'signature'
    if hint != 'auto':
        return hint, 'declared'
    return UNKNOWN, 'unknown'
