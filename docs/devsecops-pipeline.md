 # DevSecOps pipeline

The `DevSecOps Pipeline` workflow runs on pushes to `main`, `develop`, and
feature branches, and on pull requests targeting `main` or `develop`.

## Security gates

| Job | Tool | Blocking threshold |
| --- | --- | --- |
| `build-test` | Maven wrapper | `clean test` must pass |
| `sast` | Semgrep | Errors in `.semgrep.yml` fail the job |
| `secrets` | Gitleaks | Any detected secret fails the job |
| `dependency` | OWASP Dependency-Check 12.1.0 | CVSS `>= 7` fails the build |
| `image` | Trivy | Fixed `CRITICAL` findings fail the job; unfixed findings are reported but ignored |
| `policy` | GitHub Actions | Every required job must succeed |

Reports are uploaded even when a gate fails. The container image is built
locally in the runner and is never pushed by this workflow. SARIF upload is
skipped for fork pull requests because their read-only tokens cannot write to
the repository code-scanning results.

## Demonstrating a failed gate safely

Do not commit real credentials or a fake secret-like value to demonstrate
Gitleaks. To test the gate locally, create a temporary file outside the
repository and run:

```sh
docker run --rm \
  -v "$PWD:/repo" \
  -v "$PWD/../gitleaks-demo:/demo:ro" \
  zricethezav/gitleaks:v8.24.2 \
  detect --no-git --source=/demo --redact --exit-code 1
 
