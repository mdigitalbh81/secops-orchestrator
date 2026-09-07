# Third-Party Software Notices

This page documents third-party tools, libraries, container images, and software components integrated with or utilized by SecOps Orchestrator.

## Important Licensing Separation

- **SecOps Orchestrator License**: SecOps Orchestrator is licensed under its own license (PolyForm Perimeter License 1.0.1, source-available). See [LICENSE](/home/felps/projetos/secops-orchestrator/LICENSE).
- **No Sublicensing / Relicensing**: SecOps Orchestrator's PolyForm Perimeter license does not relicense third-party components. Third-party tools, dependencies, and container images are **not** relicensed under the PolyForm Perimeter License.
- **Independent Terms**: Each third-party component remains subject to its own original license, copyright notices, and terms established by respective copyright holders and upstream authors.
- **Informational Notice**: This document is provided for informational and compliance purposes only and does not replace or supersede official license texts, notices, or agreements from individual third-party projects.

---

## A. Runtime Libraries (Direct Dependencies)

All direct runtime dependencies specified in `backend/pyproject.toml` (`[project].dependencies`):

| Dependency | Version / Range | Role / Function | Official License | Upstream Source |
| :--- | :--- | :--- | :--- | :--- |
| **fastapi** | `>=0.111,<1` | Core asynchronous REST API framework | MIT | https://github.com/fastapi/fastapi |
| **uvicorn** | `[standard]>=0.30,<1` | High-performance ASGI web server | BSD-3-Clause | https://github.com/Kludex/uvicorn |
| **sqlalchemy** | `[asyncio]>=2.0,<3` | Database toolkit and Object-Relational Mapper (ORM) | MIT | https://github.com/sqlalchemy/sqlalchemy |
| **asyncpg** | `>=0.29,<1` | High-performance asynchronous PostgreSQL client driver | Apache-2.0 | https://github.com/MagicStack/asyncpg |
| **alembic** | `>=1.13,<2` | Database schema migration engine for SQLAlchemy | MIT | https://github.com/sqlalchemy/alembic |
| **pydantic** | `>=2.7,<3` | Data validation, settings parsing, and schema definitions | MIT | https://github.com/pydantic/pydantic |
| **pydantic-settings** | `>=2.3,<3` | Configuration management and environment settings | MIT | https://github.com/pydantic/pydantic-settings |
| **redis** (`redis-py`) | `>=5.0,<6` | Python client library for Valkey/Redis protocol | MIT | https://github.com/redis/redis-py |
| **arq** | `>=0.26,<1` | Asynchronous job queue dispatch and worker execution | MIT | https://github.com/python-arq/arq |
| **httpx** | `>=0.27,<1` | Asynchronous HTTP client library | BSD-3-Clause | https://github.com/encode/httpx |

> **Note on `redis` (`redis-py`) vs Valkey**: SecOps Orchestrator uses **Valkey** as its in-memory queue broker and server daemon. The Python package `redis` (`redis-py`) is used exclusively as the client library connecting to Valkey via the wire-compatible protocol. The server is Valkey; `redis-py` is the client library.

---

## B. Scanner and Security Tools

| Component | Role | License | Distribution / Execution | Upstream Source |
| :--- | :--- | :--- | :--- | :--- |
| **Semgrep** | SAST Scanner (Source code) | LGPL-2.1-only | Installed in Worker image (via pip) | https://github.com/semgrep/semgrep |
| **Trivy** | Vulnerability Scanner (Containers / Filesystems) | Apache-2.0 | Installed in Worker image (binary) | https://github.com/aquasecurity/trivy |
| **pip-audit** | SCA Scanner (Python dependencies) | Apache-2.0 | Installed in Worker image (via pip) | https://github.com/pypa/pip-audit |
| **npm CLI** | SCA Tool / Package Manager (`npm audit`) | Artistic-2.0 | Installed in Worker image (Debian package) | https://github.com/npm/cli |
| **OWASP ZAP** | DAST Scanner (Baseline web scan) | Apache-2.0 | Separate container service (`zaproxy/zap-stable`) | https://github.com/zaproxy/zaproxy |
| **Nuclei** | DAST Scanner (Fast vulnerability engine) | MIT | Installed in Worker image (binary) | https://github.com/projectdiscovery/nuclei |
| **Nuclei Templates** | Community vulnerability templates | MIT | Installed in Worker image (release archive) | https://github.com/projectdiscovery/nuclei-templates |

---

## C. Infrastructure Components

| Component | Role | License | Distribution / Execution | Upstream Source |
| :--- | :--- | :--- | :--- | :--- |
| **Valkey** | In-memory queue broker & key-value store server | BSD-3-Clause | Separate container service (`valkey/valkey:8.1.10-alpine`) | https://github.com/valkey-io/valkey |
| **PostgreSQL** | Relational database engine | PostgreSQL License | Separate container service (`postgres:16-alpine`) | https://www.postgresql.org |

> **Server / Client Architecture**: Valkey is deployed as the standalone server daemon in Docker Compose (`valkey/valkey:8.1.10-alpine`). Standalone Redis Server is not used. The application connects to Valkey using the standard client library `redis-py` (`redis>=5.0,<6`), which is fully compatible with the Valkey server protocol.

---

## D. Optional External Integrations

| Component | Role | License | Distribution Status | Upstream Source |
| :--- | :--- | :--- | :--- | :--- |
| **GitHub CodeQL CLI** | Deep SAST Scanner (Dataflow / Taint) | Proprietary / GitHub Terms | Optional external integration; NOT distributed or installed | https://github.com/github/codeql-cli-binaries |

### Special Notice: GitHub CodeQL

- **Status**: External, optional, and not distributed or installed by SecOps Orchestrator.
- **Terms**: GitHub CodeQL CLI is proprietary software governed by GitHub's own terms ([GitHub CodeQL Terms and Conditions](https://github.com/github/codeql-cli-binaries/blob/main/LICENSE.md) and [GitHub Terms of Service](https://docs.github.com/en/site-policy/github-terms/github-terms-of-service)).
- **User Responsibility**: Users who choose to download, install, or enable CodeQL in their environment are solely responsible for obtaining any necessary license and ensuring their use strictly complies with GitHub's CodeQL Terms and Conditions. SecOps Orchestrator grants no rights, licenses, or warranties for the use of CodeQL.
- **Availability Behavior**: SecOps Orchestrator detects whether the `codeql` binary is available in `PATH`. When absent, it records status as `UNAVAILABLE` and continues scan execution without error.

---

## License Notices and Attribution Compliance

### Apache License 2.0 (Trivy, pip-audit, OWASP ZAP, asyncpg)

Licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License. You may obtain a copy of the License at:

http://www.apache.org/licenses/LICENSE-2.0

Upstream NOTICE and copyright files provided in official distributions of Trivy, pip-audit, OWASP ZAP, and asyncpg are preserved within their respective containers and packages.

### MIT License (FastAPI, SQLAlchemy, Alembic, Pydantic, Pydantic-Settings, redis-py, ARQ, Nuclei, Nuclei Templates)

Permission is hereby granted, free of charge, to any person obtaining a copy of the software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, subject to conditions set forth by upstream authors:

- FastAPI: https://github.com/fastapi/fastapi/blob/master/LICENSE
- SQLAlchemy: https://github.com/sqlalchemy/sqlalchemy/blob/main/LICENSE
- Alembic: https://github.com/sqlalchemy/alembic/blob/main/LICENSE
- Pydantic: https://github.com/pydantic/pydantic/blob/main/LICENSE
- Pydantic Settings: https://github.com/pydantic/pydantic-settings/blob/main/LICENSE
- redis-py: https://github.com/redis/redis-py/blob/master/LICENSE
- ARQ: https://github.com/python-arq/arq/blob/main/LICENSE
- Nuclei: https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md
- Nuclei Templates: https://github.com/projectdiscovery/nuclei-templates/blob/main/LICENSE.md

### BSD 3-Clause License (Uvicorn, HTTPX, Valkey)

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:
1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

Upstream licenses:
- Uvicorn: https://github.com/Kludex/uvicorn/blob/master/LICENSE.md
- HTTPX: https://github.com/encode/httpx/blob/master/LICENSE.md
- Valkey: https://github.com/valkey-io/valkey/blob/unstable/COPYING

### GNU Lesser General Public License v2.1 (Semgrep CLI Engine)

Semgrep CLI is licensed under LGPL-2.1-only. The source code of upstream Semgrep is available at:

https://github.com/semgrep/semgrep

SecOps Orchestrator invokes Semgrep via external subprocess execution and does not modify, statically link, or relicense the Semgrep binary.

### Artistic License 2.0 (npm CLI)

The npm application is licensed under the Artistic License 2.0. Upstream source code and license text are available at:

https://github.com/npm/cli/blob/latest/LICENSE

### PostgreSQL License (PostgreSQL)

PostgreSQL is released under the PostgreSQL License, a liberal Open Source license similar to BSD or MIT licenses:

https://www.postgresql.org/about/licence/
