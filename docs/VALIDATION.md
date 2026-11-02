# Validation

Standalone 1.0.0 was installed into an isolated Python 3.12.16 environment and tested through its installed package.

- 73 automated tests passed. Every capability has a synthetic dispatch test; tests also cover parsed findings, input rejection, authentication routing, bounded requests, redirects, partial DNS results, literal rendering and credential-safe errors.
- The external local launcher was verified with the existing private environment file and a normal startup/exit.
- The checks below are bounded live requests. They do not constitute a complete provider or website audit. Account access and service availability can change.
- Website modules other than technology were verified with synthetic responses, not fresh live requests for every module.
- The GitHub workflow is included for Python 3.10, 3.12 and 3.13. Check GitHub Actions for its current results.

| Module | Source | Example | Outcome |
|---|---|---|---|
| 01 | Google Public DNS | example.com | Completed |
| 02 | System DNS resolver | example.com | Completed |
| 03 | ipwho.is | 8.8.8.8 | Completed |
| 04 | Internet Archive CDX | example.com | Completed |
| 20 | crt.sh JSON endpoint | example.com | Completed |
| 15 | Censys Platform API | 8.8.8.8 | Completed |
| 18 | Shodan Host API | 8.8.8.8 | Completed |
| 19 | VirusTotal API v3 | 8.8.8.8 | Completed |
| 22 | OTX Indicator API | 8.8.8.8 | Completed |
| 09 | Website headers and HTML | https://example.com | Completed |
| 09 | Website headers and HTML | https://www.python.org | Completed |

## Installed dependency versions

- requests: 2.34.2
- rich: 13.9.4
- beautifulsoup4: 4.15.0
- dnspython: 2.9.1
- pytest: 9.2.0

## Release hygiene

Source and final ZIP were checked against nonempty credentials from the existing private configuration, plus common GitHub token, Google key and private-key patterns. Zero matches were found. No private config file is included. This is a release-artifact scan, not an audit of the existing GitHub history.
