# Container architecture

```mermaid
flowchart LR
    Browser["Browser / ZAP<br/>localhost only"]
    Compose["Docker Compose"]
    Container["webgoat container<br/>non-root, read-only rootfs"]
    WebGoat["WebGoat<br/>Spring Boot :8080"]
    WebWolf["WebWolf<br/>Spring Boot :9090"]
    Volume[("webgoat-data<br/>lesson database")]
    Tmpfs[("/tmp tmpfs<br/>uploads and transient files")]

    Browser -->|"127.0.0.1:8080"| Compose
    Browser -->|"127.0.0.1:9090"| Compose
    Compose --> Container
    Container --> WebGoat
    Container --> WebWolf
    WebGoat --> Volume
    WebWolf --> Volume
    WebGoat --> Tmpfs
    WebWolf --> Tmpfs
```

Compose publishes only loopback addresses on the host. Inside the container,
both Spring Boot applications bind to `0.0.0.0` so Docker can forward traffic
without requiring custom DNS entries. The image drops all Linux capabilities,
sets `no-new-privileges`, runs as `webgoat`, and uses a named volume only for
the mutable lesson database.
