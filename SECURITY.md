# Security reporting

Report suspected credential exposure or a vulnerability through GitHub's private vulnerability reporting feature if it is available for this repository. If it is unavailable, open an issue requesting a private reporting channel without including exploit details, credentials, sensitive indicators or personal data.

For ordinary bugs, use synthetic examples and remove keys, authorization headers, private indicators and JWT claims from screenshots and logs. Rotate an exposed credential with its provider; removing a screenshot or commit alone does not invalidate it.

This tool is a local CLI, not a sandbox for untrusted URL submissions. It does not exploit targets, submit forms or bypass access controls. Network boundaries and provider-side behavior are documented in README.md. Dependency updates must pass the automated tests before release. No guaranteed response time or security certification is offered.
