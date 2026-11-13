# syntax=docker/dockerfile:1
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t routeros-acme .
# The build stage runs natively and cross-compiles (no QEMU needed).
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
# License texts of Go and of every library compiled in, the same for every platform (MIT/BSD/Apache require passing them on).
COPY LICENSE scripts/third-party-licenses.sh ./
RUN mkdir -p /out/licenses && cp LICENSE /out/licenses/ \
 && sh third-party-licenses.sh > /out/licenses/THIRD_PARTY_LICENSES.txt
ARG TARGETOS TARGETARCH TARGETVARIANT
# Shown in the web UI footer and by `routeros-acme -version`. CI passes 1.2.3 for tags, main-<sha> otherwise.
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" -o /out/routeros-acme . \
 && mkdir -p -m 700 /out/data

FROM scratch
# Links the image to the GitHub repository: on ghcr.io it then gets the repository's visibility and access.
LABEL org.opencontainers.image.source="https://github.com/HenrikValstedt/routeros-acme" \
      org.opencontainers.image.title="RouterOS ACME" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.description="Self-hosted Let's Encrypt certificate management for MikroTik RouterOS, with a web UI and secure device enrollment"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/routeros-acme /routeros-acme
COPY --from=build /out/licenses /licenses
# A new volume starts out owned by the unprivileged user. The container still starts as
# root: it reads SECRET_KEY_FILE, hands /data to user 65532 (also for data from older
# versions), then drops to that user for good before serving. See README "Hardened setup".
COPY --from=build --chown=65532:65532 /out/data /data
ENV DATA_DIR=/data LISTEN=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=1m --timeout=5s CMD ["/routeros-acme", "-healthcheck"]
ENTRYPOINT ["/routeros-acme"]
