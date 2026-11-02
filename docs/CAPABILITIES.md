# Capability reference

| No. | Capability | Required input | Source | Credential |
|---|---|---|---|---|
| 01 | DNS over HTTPS | Bare domain, without a URL or email | Google Public DNS | None |
| 02 | DNS and Email Records | Bare domain, without a URL or email | System DNS resolver | None |
| 03 | IP and ASN Information | IPv4 or IPv6 address | ipwho.is | None |
| 04 | Archive History | Bare domain, without a URL or email | Internet Archive CDX | None |
| 05 | Cookie Attributes | Public website domain or HTTP(S) origin, without a path | Website response | None |
| 06 | Robots Instructions | Public website domain or HTTP(S) origin, without a path | Website /robots.txt | None |
| 07 | Sitemap Locations | Public website domain or HTTP(S) origin, without a path | Website /sitemap.xml | None |
| 08 | Social Links | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 09 | Technology and Integrations | Public website domain or HTTP(S) origin, without a path | Website headers and HTML | None |
| 10 | Forms and Autocomplete | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 11 | HTML Comments | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 12 | CAPTCHA Indicators | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 13 | Embedded Objects | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 14 | Tracking Pixel Hints | Public website domain or HTTP(S) origin, without a path | Website HTML | None |
| 15 | Censys Host Records | IPv4 or IPv6 address | Censys Platform API | CENSYS_PAT |
| 16 | HTTP Headers and Security | Public website domain or HTTP(S) origin, without a path | Website response | None |
| 17 | Security Contact File | Public website domain or HTTP(S) origin, without a path | Website /.well-known/security.txt | None |
| 18 | Shodan Host Records | IPv4 or IPv6 address | Shodan Host API | SHODAN_API_KEY |
| 19 | VirusTotal Reports | IP address or domain | VirusTotal API v3 | VIRUSTOTAL_API_KEY |
| 20 | Certificate Transparency | Bare domain, without a URL or email | crt.sh JSON endpoint | None |
| 21 | JWT Inspector | Three-part JWT; decoded locally, not verified | Offline decoder (no signature verification) | None |
| 22 | AlienVault OTX Intelligence | IP, domain, or hexadecimal MD5/SHA-1/SHA-256 | OTX Indicator API | OTX_API_KEY |

Provider modules query fixed HTTPS endpoints. Website modules inspect one response. No discovered resources are fetched.
Google API keys are not required or consumed; Censys uses CENSYS_PAT, not legacy ID/secret credentials.
