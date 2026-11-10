# Building RouterOS ACME

This file lists everything needed to build the container image, the commands, and what was verified.
Last verified: **2026-11-10**.

## 1. Prerequisites

### Container image (the normal way)

| Requirement | Minimum | Verified with | Why |
|---|---|---|---|
| Docker Engine | 23 (BuildKit default) | **29.1.3** (Ubuntu `docker.io` 29.1.3-0ubuntu4.1) | builds and runs the image |
| BuildKit | bundled with Engine | v0.26.2 | multi-stage build, `--platform` |
| docker buildx plugin | 0.10+ | **0.30.1** (Ubuntu `docker-buildx`) | multi-architecture builds |
| Docker Compose v2 | 2.20+ | **2.40.3** (Ubuntu `docker-compose-v2`) | `docker compose up` with `docker-compose.yml` |
| containerd image store | only for local multi-arch | enabled (default on new Docker 29 installs) | keeps all architectures in one local image (`docker image ls --tree`) |
| Disk | ~0.6 GB | – | `golang:1.26-alpine` base (364 MB unpacked) plus build cache |
| RAM | 1 GB | – | Go compiler |

**Not needed:** QEMU or binfmt emulation. The Dockerfile cross-compiles in the build stage, and the final stage
has no `RUN` steps, so arm64 and arm/v7 images build natively on an x86-64 machine (and the other way round).

**Network access during the build:**

| Host | What |
|---|---|
| `registry-1.docker.io` (Docker Hub) | base image `golang:1.26-alpine` (~72 MB download) |
| `dl-cdn.alpinelinux.org` | `apk add ca-certificates` |
| `proxy.golang.org`, `sum.golang.org` | Go modules from `go.mod`, checked against `go.sum` |

Behind an HTTP proxy, pass Docker's built-in build args: `--build-arg HTTPS_PROXY=http://proxy:3128 --build-arg NO_PROXY=...`.

**Pinned inputs:** base image tag `golang:1.26-alpine` (resolved to
`sha256:87c65a688975c0b1d4585d204874c45ca78354670e3a5f11368c5a492303d696` on 2026-11-10). Go modules are pinned
in `go.mod`/`go.sum`: lego v4.35.2, golang.org/x/crypto v0.58.0, github.com/pkg/sftp v1.13.12. The final image is
`FROM scratch`: the program, the CA bundle, and nothing else.

### Installing the prerequisites on Ubuntu (24.04 / 26.04)

```sh
sudo apt-get update
sudo apt-get install -y docker.io docker-buildx docker-compose-v2
sudo usermod -aG docker $USER      # then log out and in again
```

Until you log in again, run Docker commands through the new group: `sg docker -c 'docker ps'`.
On Debian/other distributions, Docker's own repository (`docker-ce`, `docker-buildx-plugin`,
`docker-compose-plugin`) works the same way.

### Development without Docker (optional)

| Requirement | Verified with | For |
|---|---|---|
| Go | 1.26+ (tested with 1.27.3) | `go build`, `go test ./...` |
| QEMU/KVM + MikroTik CHR image | qemu 10.x, CHR 7.25.1 | optional real-router test (`TestRealRouterOS`) |

## 2. Build

All commands run in the project folder.

**Image for this machine:**
```sh
docker build -t routeros-acme:latest .
```

**Build and start with Compose** (uses `docker-compose.yml`, data in `./data`):
```sh
docker compose up -d --build
docker compose logs | grep "Setup code"
```

**All three architectures, kept locally** (needs the containerd image store):
```sh
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t routeros-acme:latest .
docker image ls --tree routeros-acme:latest
```

**All three architectures, pushed to a registry:**
```sh
docker login registry.example.com
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 \
  -t registry.example.com/you/routeros-acme:latest --push .
```

**Carry the image to a server without a registry:**
```sh
docker save routeros-acme:latest -o dist/routeros-acme-multiarch.tar     # here
scp dist/routeros-acme-multiarch.tar server:
docker load -i routeros-acme-multiarch.tar                               # on the server
```
Then copy `docker-compose.yml` to the server, remove its `build: .` line, and run `docker compose up -d`.

**Check that a variant holds the right CPU architecture:**
```sh
c=$(docker create --platform linux/arm64 routeros-acme:latest)
docker cp $c:/routeros-acme ./routeros-acme-arm64 && docker rm $c
file ./routeros-acme-arm64        # ELF 64-bit LSB executable, ARM aarch64
```

## 3. Results (2026-11-10)

| Platform | Download (compressed) | On disk | Program |
|---|---|---|---|
| linux/amd64 | 4.17 MB | 14.4 MB | ELF x86-64 |
| linux/arm64 | 3.80 MB | 13.3 MB | ELF ARM aarch64 |
| linux/arm/v7 | 3.99 MB | 13.8 MB | ELF 32-bit ARM EABI5 |

- First build ~50 s (base image download), multi-arch rebuild ~30 s. The amd64 build was byte-for-byte reproducible.
- `dist/routeros-acme-multiarch.tar`: 11.2 MB, all three platforms. SHA-256 is in the `.sha256` file beside it.

**Verified with the built amd64 image:**
- `docker compose up` → container **healthy** (built-in `-healthcheck`), first-run setup code in the log, web UI on :8080.
- First-run setup, then **enrolled a RouterOS 7.25.1 router** from inside the container (all 8 steps), pinned api-ssl test.
- **Deployed a certificate** from the container: `www-ssl` and `api-ssl` switched to it, and the pin was updated.
- The admin password used for enrollment appears **nowhere** in the data volume.
- **TLS to Let's Encrypt** works with the bundled CA certificates (staging server reached).
- Sessions are dropped on container restart (by design), so you sign in again.

**Not verified:** running the arm64 and arm/v7 images on real ARM hardware. Their programs were checked
for the right architecture, and the same code is tested on amd64.

## 4. Notes for running

- The container runs as root, so files in `./data` are root-owned with mode 0600. Read or back them up with `sudo`.
- Back up `data/secret.key` separately from `config.json`. Without it, enrolled routers must be enrolled again.
- See `README.md` for configuration, reverse proxies and device enrollment.
