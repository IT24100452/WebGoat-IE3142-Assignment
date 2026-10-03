# Secret management

The repository contains no runtime credentials. `.env.example` documents
configuration names and safe local defaults only; create a private `.env`
from it for local Compose runs:

```text
Copy-Item .env.example .env
docker compose config
```

`.env`, private evidence, key material, and scanner caches are ignored by
Git. The tracked `.env.example` is the only environment file allowlisted in
`.gitleaks.toml`; documentation and evidence are intentionally scanned rather
than globally excluded. Never replace a placeholder with a real credential
in a commit or test fixture.

For CI, provide only the variable names required by the workflow through
GitHub Actions secrets or environment settings. The workflow uses
`GITHUB_TOKEN` through the runner context and does not store its value in the
repository. Run the same local secret check before opening a pull request:

```text
gitleaks detect --config .gitleaks.toml --redact --no-banner
```

If a secret is detected, revoke or rotate it first, remove it from the
working tree and history according to the repository incident process, then
rerun Gitleaks. Do not add a broad path allowlist to make a finding disappear.
