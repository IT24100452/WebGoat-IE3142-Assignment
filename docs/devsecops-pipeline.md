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
