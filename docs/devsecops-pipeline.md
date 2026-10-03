# DevSecOps pipeline

The DevSecOps workflow runs on pushes to `main`, `develop`, and feature branches,
pull requests targeting `main` or `develop`, and manual dispatch. It builds and tests
the application, runs Semgrep and Gitleaks, checks dependencies, builds the
container, and uses Trivy for dependency and image scanning. The required policy job
fails unless each security job succeeds.

## Security gates

|     Job      |              Tool               |                              Blocking threshold                              |
|--------------|---------------------------------|------------------------------------------------------------------------------|
| `build-test` | Maven wrapper                   | `clean test` must pass                                                       |
| `sast`       | Semgrep                         | Errors in `.semgrep.yml` fail the job                                        |
| `secrets`    | Gitleaks                        | Any detected secret fails the job, except the documented historical baseline |
| `dependency` | OWASP Dependency-Check or Trivy | CVSS 7+ or fixed HIGH/CRITICAL findings fail                                 |
| `image`      | Trivy                           | Fixed CRITICAL findings fail the job                                         |
| `policy`     | GitHub Actions                  | Every required job must succeed                                              |

The build job packages the application and passes its JAR to the container job as an
artifact. Trivy SARIF is uploaded only after a successful image scan has produced a
report, so an earlier image-build failure is reported at its source. Reports are
uploaded as workflow artifacts rather than committed. The container image is built
locally and is not pushed by this workflow.

When the repository has an `NVD_API_KEY` Actions secret, dependency analysis uses
OWASP Dependency-Check and fails for findings at CVSS 7 or higher. Without the
secret, the workflow uses Trivy's filesystem vulnerability scanner for Maven
dependencies, failing on fixed HIGH or CRITICAL findings. No API key is stored in
the repository.

Gitleaks scans the full Git history. Its configuration allowlists only the exact
historical commits that produced the repository's existing lesson/example findings;
future commits are still scanned. If any historical credential was real, it should
also be treated as exposed and revoked independently of this scan baseline.

The dependency and image scans intentionally ignore the XStream CVEs used by the
Vulnerable Components lesson. The XStream version must remain vulnerable for that
lesson; all other reported dependencies are gated, with Jackson and Tomcat pinned to
patched versions. Semgrep similarly excludes only the deliberately vulnerable lesson
examples and test fixtures from its generic hardcoded-credential, SQL-concatenation,
and command-execution rules.

## Demonstrating a failed gate safely

Do not commit real credentials or a fake secret-like value to demonstrate Gitleaks.
To test the gate locally, create a temporary file outside the repository and run:

```sh
docker run --rm \
  -v "$PWD:/repo" \
  -v "$PWD/../gitleaks-demo:/demo:ro" \
  zricethezav/gitleaks:v8.24.2 \
  detect --no-git --source=/demo --redact --exit-code 1
```

