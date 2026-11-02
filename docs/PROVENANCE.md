# Implementation provenance

This standalone edition was authored in a new directory for Neil Machado, with AI assistance, from the requested behavioral specification and provider interface references. It uses a new `hawk` package, capability dataclasses, an injected request gateway, typed result objects, independent dispatch and new synthetic tests. No old repository files, assets, catalog JSON, test files or git history were copied into this project. The user-supplied legal disclaimer is retained verbatim in substance; API names, protocol fields and environment variable names necessarily overlap.

The assistant had previously inspected and modified the Argus-derived implementation. This work is therefore **not represented as a formally isolated clean-room implementation**. Fresh files and different structure alone cannot prove the absence of all copyright concerns. This document records the method, not a legal determination.

The earlier Argus-derived source and its MIT notices remain unchanged. Existing private configuration is loaded by an external local launcher solely for interoperability; it is not part of the public package. Dependencies (Requests, Rich, Beautiful Soup and dnspython) are installed from their distributions rather than vendored. Their authors retain credit and license rights.

Product ownership/maintenance credit: Neil Machado. Implementation assistance: OpenAI Codex. This standalone release is published separately from the earlier Argus-derived repository.
