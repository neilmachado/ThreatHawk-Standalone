# Moving to the standalone edition

All 22 retained capabilities have standalone equivalents. Numbers, accepted input categories and API environment variables are preserved. Labels and result field names have changed; this is not a drop-in JSON-output API.

| No. | Earlier capability | Standalone capability |
|---|---|---|
| 01 | DNS Over HTTPS | DNS over HTTPS |
| 02 | DNS & Email Records | DNS and Email Records |
| 03 | IP & ASN Information | IP and ASN Information |
| 04 | Archive History | Archive History |
| 05 | Cookies Analyzer | Cookie Attributes |
| 06 | Robots.txt Analyzer | Robots Instructions |
| 07 | Sitemap Parsing | Sitemap Locations |
| 08 | Social Links Inspection | Social Links |
| 09 | Technology & Integrations | Technology and Integrations |
| 10 | Form & Autocomplete Inspection | Forms and Autocomplete |
| 11 | HTML Comments Extractor | HTML Comments |
| 12 | CAPTCHA Presence Checker | CAPTCHA Indicators |
| 13 | Embedded Object Hunter | Embedded Objects |
| 14 | Pixel Tracker Finder | Tracking Pixel Hints |
| 15 | Censys Host Records | Censys Host Records |
| 16 | HTTP Security & Headers | HTTP Headers and Security |
| 17 | Security.txt Check | Security Contact File |
| 18 | Shodan Host Records | Shodan Host Records |
| 19 | VirusTotal Record Lookup | VirusTotal Reports |
| 20 | CT Log Query | Certificate Transparency |
| 21 | JWT Offline Decoder | JWT Inspector |
| 22 | AlienVault OTX Threat Intelligence | AlienVault OTX Intelligence |

## What remains available

- Four home options and contextual input prompts with examples, provider names and credential status.
- Results in terminal tables; no result exports, application run logs or disk response cache.
- Censys PAT, Shodan, VirusTotal and OTX integration using the existing environment variable names.
- Manual same-site HTTPS redirect requests, bounded website observations and offline JWT decoding.
- Startup disclaimer, MIT license, automated tests and GitHub Actions.

## Installation and credentials

A fresh clone installs independently with `pip install .`. Run `threathawk`, `threathawk-new`, or `python -m hawk`. No code, asset, package or GitHub URL from the old repository is required at runtime.

The supplied local standalone launcher lives outside this repository and reads the existing private environment file. Deleting the old GitHub repository does not delete this local file. Preserve that file and the standalone virtual environment when cleaning up local folders. Credentials are deliberately not migrated into GitHub. A new computer needs its own private configuration.

Use `CENSYS_PAT`, `SHODAN_API_KEY`, `VIRUSTOTAL_API_KEY` and `OTX_API_KEY`. The old Google API key is unused. Legacy Censys ID/secret credentials are not used.

## Intentional differences

- Public branding is text-only. The old local portrait is not bundled in this edition.
- The `argus` command is not provided. Use `threathawk` in the new environment.
- Original intrusive modules, unused command helpers and the original git history are not migrated.
- Website and intelligence results remain observations, with provider access and availability limits. VirusTotal query handling is described in the README.
- The current standalone source has 71 tests; it does not import the earlier test suite.

## Before deleting the previous GitHub repository

This audit found no issues or releases in the previous repository. Its git history and repository metadata are not transferred. A local source ZIP of the earlier distribution is retained separately with its original notices; it is not a complete GitHub history backup. Deleting the repository does not remove license duties attached to previously distributed copies.
