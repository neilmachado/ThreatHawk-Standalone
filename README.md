# ThreatHawk — Standalone Edition

Created and maintained by **Neil Machado**.
A guided terminal toolkit for indicator research, DNS records, offline JWT inspection and bounded website observations. Version 1.0.0 provides 22 numbered capabilities.

[Security](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## Start

Use Python 3.10 or later:

```sh
git clone https://github.com/neilmachado/ThreatHawk-Standalone.git
cd ThreatHawk-Standalone
python3 -m venv .venv
source .venv/bin/activate
pip install .
# Load your existing trusted private environment file (outside this project):
source /path/to/your/private-config.env
threathawk
```

You can also run `threathawk-new` or `python -m hawk`. All three commands launch the same interface.

The application reads environment variables. It does not copy or auto-execute configuration files. The separately supplied local launcher reads your private environment file; no keys are included here. The `.env.example` contains names only. If your file uses assignments without `export`, use `set -a` before sourcing and `set +a` afterwards.

## Workflow

1. **View modules** — browse the numbered catalog.
2. **Select module** — choose 01–22 and see the input type, example, source and key status.
3. **Run module** — return to the selected module's input prompt.
4. **Exit**.

Inside a module, type a domain, IP, website origin, JWT or hash as indicated. Enter shows guidance, `b` returns home and `q` exits. After a same-site HTTPS/`www` redirect, `r` makes a separate request only when explicitly entered. Results appear as labeled terminal tables. Empty collections, incomplete queries, provider errors and unavailable pages are distinguished.

Display is limited to 500 rows, 4,000 characters per field and 12 nested levels, with omission notices. No result files or application run logs are written. Shell history, terminal capture and service logs are outside the application's control.

## Modules

See [the capability reference](docs/CAPABILITIES.md) for all 22 modules and credentials. Provider access depends on account plans and quotas; “configured” does not mean the key was verified.

## Boundaries

Website modules make one GET per execution, with no automatic redirects/retries, resource loading, JavaScript, form submissions or crawling. TLS verification remains enabled. Responses are limited to 2 MB; socket timeouts and an additional streaming budget bound requests. This is a local CLI, not a server-side URL-fetching service or a DNS-rebinding-resistant sandbox. DNS uses bounded resolver calls; resolver retries may occur internally.

No exploitation, password attacks, port scanning or scan-submission endpoints are implemented. External provider behavior is separate: **VirusTotal documents that queried indicators may be scanned and added to its dataset**. Do not send confidential indicators. Intelligence associations and missing records do not establish maliciousness or safety. HTML and header hints are observations, not a vulnerability assessment. JWT decoding does not validate signatures or claims. Cookie analysis omits values and may be incomplete when headers are combined.

## ⚠️ WARNING: LEGAL DISCLAIMER

This tool is intended for **educational and ethical use only**. The author is not liable for any illegal use or misuse of this tool. Users are solely responsible for their actions and must ensure they have explicit permission to scan the target systems.

## Development

```sh
pip install '.[test]'
python -m pytest tests -q
```

Tests use synthetic responses and injected clients; they do not consume provider quotas. See [validation](docs/VALIDATION.md), [implementation provenance](docs/PROVENANCE.md) and [provider references](docs/REFERENCES.md).

## License and attribution

New project source is offered under MIT; see LICENSE. Third-party libraries and services remain their authors' work and retain their own licenses/terms. No claim of legal certification or exclusive ownership of underlying libraries or general techniques is made.
