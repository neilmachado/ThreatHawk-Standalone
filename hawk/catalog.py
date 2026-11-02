"""Product capabilities, independent of dispatch and presentation."""
from dataclasses import dataclass

@dataclass(frozen=True)
class Capability:
    number: int
    title: str
    kind: str
    source: str
    action: str
    credential: str = ""

DEFINITIONS = [
 ("DNS over HTTPS", "domain", "Google Public DNS", "doh"),
 ("DNS and Email Records", "domain", "System DNS resolver", "dns"),
 ("IP and ASN Information", "ip", "ipwho.is", "ip"),
 ("Archive History", "domain", "Internet Archive CDX", "archive"),
 ("Cookie Attributes", "website", "Website response", "cookies"),
 ("Robots Instructions", "website", "Website /robots.txt", "robots"),
 ("Sitemap Locations", "website", "Website /sitemap.xml", "sitemap"),
 ("Social Links", "website", "Website HTML", "social"),
 ("Technology and Integrations", "website", "Website headers and HTML", "technology"),
 ("Forms and Autocomplete", "website", "Website HTML", "forms"),
 ("HTML Comments", "website", "Website HTML", "comments"),
 ("CAPTCHA Indicators", "website", "Website HTML", "captcha"),
 ("Embedded Objects", "website", "Website HTML", "embeds"),
 ("Tracking Pixel Hints", "website", "Website HTML", "pixels"),
 ("Censys Host Records", "ip", "Censys Platform API", "censys", "CENSYS_PAT"),
 ("HTTP Headers and Security", "website", "Website response", "headers"),
 ("Security Contact File", "website", "Website /.well-known/security.txt", "security"),
 ("Shodan Host Records", "ip", "Shodan Host API", "shodan", "SHODAN_API_KEY"),
 ("VirusTotal Reports", "indicator", "VirusTotal API v3", "vt", "VIRUSTOTAL_API_KEY"),
 ("Certificate Transparency", "domain", "crt.sh JSON endpoint", "ct"),
 ("JWT Inspector", "jwt", "Offline decoder (no signature verification)", "jwt"),
 ("AlienVault OTX Intelligence", "otx", "OTX Indicator API", "otx", "OTX_API_KEY"),
]
CATALOG = tuple(Capability(i, *row) for i, row in enumerate(DEFINITIONS, 1))
HINTS = {
 "domain": ("Bare domain, without a URL or email", "example.com"),
 "ip": ("IPv4 or IPv6 address", "8.8.8.8"),
 "website": ("Public website domain or HTTP(S) origin, without a path", "https://example.com"),
 "indicator": ("IP address or domain", "8.8.8.8"),
 "otx": ("IP, domain, or hexadecimal MD5/SHA-1/SHA-256", "example.com"),
 "jwt": ("Three-part JWT; decoded locally, not verified", "eyJhbGciOiJub25lIn0.eyJzdWIiOiJkZW1vIn0."),
}
