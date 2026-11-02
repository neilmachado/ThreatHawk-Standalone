import base64
import ipaddress
import json
import re
from urllib.parse import urlsplit


def hostname(text):
    try:
        ipaddress.ip_address(text)
    except ValueError:
        pass
    else:
        raise ValueError("A domain is required here; choose an IP module for addresses.")
    try:
        name = text.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:
        raise ValueError("Domain encoding is invalid.") from None
    if len(name) > 253 or '.' not in name or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', part) for part in name.split('.')):
        raise ValueError("Use a domain such as example.com; omit https://, paths and email prefixes.")
    return name


def origin(text):
    parsed = urlsplit(text if '://' in text else 'https://' + text)
    if parsed.scheme not in {'http', 'https'} or parsed.username is not None or parsed.password is not None or parsed.query or parsed.fragment or parsed.path not in {'', '/'}:
        raise ValueError("Use only a website origin, such as https://example.com.")
    if parsed.port not in {None, 443 if parsed.scheme == 'https' else 80}:
        raise ValueError("Custom ports are not supported.")
    host = parsed.hostname or ''
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        host = hostname(host)
    else:
        if not address.is_global:
            raise ValueError("Website checks require a public address.")
        host = '[' + str(address) + ']' if address.version == 6 else str(address)
    return parsed.scheme + '://' + host


def jwt_parts(text):
    if len(text) > 65536 or len(text.split('.')) != 3:
        raise ValueError("Use a three-part JWT shorter than 64 KB.")
    try:
        parts = [json.loads(base64.b64decode(s + '='*(-len(s)%4), altchars=b'-_', validate=True)) for s in text.split('.')[:2]]
        if not all(isinstance(v, dict) for v in parts):
            raise ValueError()
        return {'Header': parts[0], 'Claims': parts[1], 'Verification': 'Not verified; decoding is not authentication.'}
    except (ValueError, UnicodeError):
        raise ValueError("JWT header and claims must be base64url JSON objects.") from None


def normalize(kind, text):
    text = text.strip()
    if not text or any(ord(c) < 32 for c in text):
        raise ValueError("Enter a nonempty value without control characters.")
    if kind == 'website':
        return origin(text)
    if kind == 'jwt':
        jwt_parts(text)
        return text
    if kind in {'ip', 'indicator', 'otx'}:
        try:
            return str(ipaddress.ip_address(text))
        except ValueError:
            if kind == 'ip':
                raise ValueError("Enter an IPv4 or IPv6 address, for example 8.8.8.8.") from None
    if kind == 'otx' and re.fullmatch(r'(?:[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64})', text):
        return text.lower()
    return hostname(text)
