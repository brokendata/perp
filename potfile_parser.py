"""Byte-safe potfile boundaries shared by perp and potofgold (parser revision 2).

Hashcat dialect follows src/potfile.c: final separator plus $HEX[] decoding.
Auto supports the explicitly listed structures; it rejects unknown multi-field
layouts rather than guessing which field contains the recovered password.
"""
from functools import lru_cache
import re

PARSER_REVISION = 2
H = rb"[0-9a-fA-F]"
# These describe complete hash representations, not arbitrary colon counts.
# Kerberos layouts follow Hashcat modules 13100/19600/19700/18200.
STRUCTURES = (
    rb"\$krb5tgs\$23\$(?:\*[^*\r\n]+\*\$)?" + H + rb"{32}\$(?:" + H + rb"{2}){16,20480}",
    rb"\$krb5tgs\$(?:17|18)\$[^$\r\n]+\$[^$\r\n]+\$(?:\*[^*\r\n]+\*\$)?" + H + rb"{24}\$(?:" + H + rb"{2}){32,20480}",
    rb"\$krb5asrep\$23\$[^\r\n]+?:" + H + rb"{32}\$(?:" + H + rb"{2}){16,20480}",
    rb"[^:\r\n]+::[^:\r\n]*:" + H + rb"{16}:" + H + rb"{32}:(?:" + H + rb"{2}){16,}",
    rb"[^:\r\n]+::[^:\r\n]*:" + H + rb"{48}:" + H + rb"{48}:" + H + rb"{16}",
)


@lru_cache(maxsize=16)
def patterns(separator):
    return tuple(re.compile(rb"^(?:" + pattern + rb")(?=" + re.escape(separator) + rb")") for pattern in STRUCTURES)


def decode_password(password: bytes) -> bytes:
    if password.startswith(b"$HEX[") and password.endswith(b"]"):
        value = password[5:-1]
        if not re.fullmatch(rb"(?:[0-9a-fA-F]{2})*", value):
            raise ValueError("Invalid $HEX[] password")
        return bytes.fromhex(value.decode("ascii"))
    return password


def parse_record(line: bytes, separator=b":", field=None, dialect="auto"):
    if not separator or b"\r" in separator or b"\n" in separator:
        raise ValueError("Separator must be nonempty and cannot contain a newline")
    if dialect not in {"auto", "hashcat", "john"}:
        raise ValueError("Unknown potfile dialect")
    if field is not None:
        if field < 1:
            raise ValueError("Password field must be at least 1")
        parts = line.split(separator, field)
        if len(parts) != field + 1 or not parts[0]:
            raise ValueError("Missing configured password boundary")
        hash_part, password = separator.join(parts[:-1]), parts[-1]
    elif dialect == "hashcat":
        # Only appropriate for canonical Hashcat potfiles: passwords containing
        # the separator are HEX-encoded by Hashcat, so it belongs to the hash.
        hash_part, boundary, password = line.rpartition(separator)
        if not boundary or not hash_part:
            raise ValueError("Missing Hashcat potfile boundary")
    else:
        recognized = {match.end() for pattern in patterns(separator) if (match := pattern.match(line))}
        if len(recognized) > 1:
            raise ValueError("Ambiguous structured hash boundary")
        if recognized:
            end = recognized.pop()
            hash_part, password = line[:end], line[end + len(separator):]
        else:
            # Never let a malformed structured hash fall back to a port, salt,
            # username, or service field that merely happens to contain a colon.
            if line.startswith((b"$krb5",)) or b"::" in line:
                raise ValueError("Unsupported or malformed structured hash; specify its layout")
            if line.count(separator) != 1:
                raise ValueError("Ambiguous potfile boundary; use --format hashcat for canonical Hashcat data or an explicit --password-field")
            hash_part, _, password = line.partition(separator)
            if not hash_part:
                raise ValueError("Empty hash field")
    return hash_part, decode_password(password)
