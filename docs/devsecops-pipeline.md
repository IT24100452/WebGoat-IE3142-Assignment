# DevSecOps pipeline

The DevSecOps workflow runs on pushes and pull requests for every branch, as well as
manual dispatch. It builds and tests the application, runs Semgrep and Gitleaks,
checks dependencies, builds the container, and uses Trivy for dependency and image
scanning. The required policy job fails unless each security job succeeds.

The build job packages the application and passes its JAR to the container job as an
artifact. Trivy SARIF is uploaded only after a successful image scan has produced a
report, so an earlier image-build failure is reported at its source.

When the repository has an `NVD_API_KEY` Actions secret, dependency analysis uses OWASP
Dependency-Check and fails for findings at CVSS 7 or higher. Without the secret, the
workflow uses Trivy's filesystem vulnerability scanner for Maven dependencies, failing
on fixed HIGH or CRITICAL findings. No API key is stored in the repository.

Generated scan and test reports are kept as workflow artifacts rather than committed.

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
