# STRIDE threat model and control mapping

This register covers the four secure-coding cases in the Security Misconfiguration lesson.
Ratings use likelihood and impact on a 1-5 scale; risk is their product.

|           Case           |         STRIDE         |                                                                    Threat and evidence                                                                     | L | I |        Risk |                                                                                         Control and verification                                                                                         |
|--------------------------|------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------|--:|--:|------------:|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 - default credentials  | Elevation of privilege | `DefaultCredentialsTask.login` previously accepted `admin/admin`, granting the staging admin profile.                                                      | 4 | 5 |   20 (High) | Remove built-in credentials; provision accounts through the deployment secret store. `DefaultCredentialsTaskTest.shouldRejectDefaultCredentials` verifies the former pair cannot authenticate.           |
| 2 - verbose errors       | Information disclosure | `VerboseErrorTask.triggerError` previously returned a stack trace containing environment values and `SYSTEM_API_TOKEN`; `fetchConfig` accepted that token. | 4 | 4 |   16 (High) | Return a generic 500 response, keep diagnostics server-side, and deny configuration access. `VerboseErrorTaskTest` verifies no secret/stack-trace markers are returned and the former token is rejected. |
| 3 - actuator exposure    | Information disclosure | `ActuatorExposureTask.actuatorEnv` exposes the internal API key.                                                                                           | 3 | 5 |   15 (High) | Restrict actuator endpoints and redact secrets; verification belongs to Member 3's case-3 regression tests.                                                                                              |
| 4 - unsafe configuration | Elevation of privilege | `ConfigHardeningTask.submitConfig` models debug and default-user settings that can expose administrative functionality.                                    | 3 | 4 | 12 (Medium) | Disable debug endpoints, hide health details, and remove default users; verification belongs to Member 3's case-4 regression tests.                                                                      |

## STRIDE coverage

- **Spoofing:** Cases 1 and 4 address unauthenticated/default administrative access.
- **Tampering:** A default account or exposed management endpoint can enable unauthorized changes.
- **Repudiation:** Generic client errors avoid leaking internals; server logs retain diagnostic detail.
- **Information disclosure:** Cases 2 and 3 prevent stack traces, environment values, and API keys from reaching clients.
- **Denial of service:** Not represented by these four lesson cases; rate limiting and resource quotas remain deployment controls.
- **Elevation of privilege:** Cases 1 and 4 remove default administrative paths.

## Evidence and limitations

The regression tests are executable fixed-state evidence. Baseline behavior is recorded by the
pre-fix assertions in the lesson implementation history; no real credentials or token values
should be copied into reports. SAST and integration-scan counts must be added from the CI run
that evaluates the merged branch.
