# syntax=docker/dockerfile:1
# Multi-arch: docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t routeros-acme .
# The build stage runs natively and cross-compiles (no QEMU needed).
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
RUN apk add --no-cache ca-certificates
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
COPY web ./web
ARG TARGETOS TARGETARCH TARGETVARIANT
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=${TARGETVARIANT#v} \
    go build -trimpath -ldflags="-s -w" -o /out/routeros-acme .

FROM scratch
# Links the image to the GitHub repository: on ghcr.io it then gets the repository's visibility and access.
LABEL org.opencontainers.image.source="https://github.com/HenrikValstedt/routeros-acme" \
      org.opencontainers.image.title="RouterOS ACME" \
      org.opencontainers.image.description="Self-hosted Let's Encrypt certificate management for MikroTik RouterOS, with a web UI and secure device enrollment"
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /out/routeros-acme /routeros-acme
ENV DATA_DIR=/data LISTEN=:8080
VOLUME /data
EXPOSE 8080
HEALTHCHECK --interval=1m --timeout=5s CMD ["/routeros-acme", "-healthcheck"]
ENTRYPOINT ["/routeros-acme"]
