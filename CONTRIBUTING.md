# Contributing

Open an issue describing the proposed behavior before a substantial change. Include the affected module number and a synthetic input for bug reports; never submit API keys or confidential provider responses.

Create a virtual environment, install with `python -m pip install '.[test]'`, and run `python -m pytest tests -q`. Tests must use fixtures or injected clients, not live keys or paid provider requests.

Keep the numbered catalog, source labels, input guidance and capability documentation consistent. Preserve bounded requests, explicit redirect handling, credential-safe error messages, terminal-only results and the exclusion of intrusive scans. New provider integrations should cite official interface documentation and distinguish unavailable results from empty findings.

Submit a pull request describing the behavior change and validation. Preserve notices for third-party work; do not introduce copied implementation or assets without reviewing their license and documenting their origin.
