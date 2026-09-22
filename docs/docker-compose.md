# Docker Compose runbook

The repository Compose stack builds the WebGoat image from the Maven artifact
in `target/` and runs WebGoat and WebWolf in one container. It is intentionally
bound to the host loopback interface so the deliberately vulnerable training
application is not exposed to the local network.

## Build and start

From the repository root:

```shell
./mvnw --batch-mode --no-transfer-progress -DskipTests package
docker compose config
docker compose build
docker compose up -d
docker compose ps
```

On Windows, use `mvnw.cmd` for the Maven command. The image is tagged
`ie3142-webgoat:local` by default. Set `IMAGE_TAG` to use another local tag.
`WEBGOAT_VERSION` must match the Maven project version when building a
different release or snapshot; it controls the writable database directory
used by both the image and Compose volume.

The readiness check is available at
`http://127.0.0.1:8080/WebGoat/actuator/health`; the browser entry points are
`http://127.0.0.1:8080/WebGoat/` and
`http://127.0.0.1:9090/WebWolf/`. The container health check tolerates the
application's startup period and falls back to the WebGoat context root for
versions where the actuator route is not available

## Configuration and teardown

Copy `.env.example` to `.env` before changing ports or the timezone. The
`WEBGOAT_HOST` and `WEBWOLF_HOST` values are container bind addresses and
should normally remain `0.0.0.0`; host exposure is controlled separately by
the `127.0.0.1:` port mappings. For proxy-based exercises, add host aliases
such as `www.webgoat.local` and `www.webwolf.local` to the host machine and
set the corresponding application URL configuration as required.

```shell
docker compose logs --follow webgoat
docker compose down
docker compose down -v  # also remove the disposable lesson database
```

## Evidence capture

Record the exact commit and commands used for the report:

```shell
mkdir -p evidence/generated
git rev-parse HEAD | tee evidence/generated/commit.txt
docker compose config > evidence/generated/compose-config.txt
docker compose ps > evidence/generated/compose-ps.txt
curl --fail http://127.0.0.1:8080/WebGoat/actuator/health \
  > evidence/generated/webgoat-health.json
```
