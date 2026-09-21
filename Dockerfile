# syntax=docker/dockerfile:1

# Build stage. The official image sets GOTOOLCHAIN=local, so the base tag must
# satisfy the go directive in go.mod (see spec §3.4 / B15).
FROM golang:1.27-alpine AS builder

ARG VERSION=dev
ARG COMMIT=none
ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apk add --no-cache git ca-certificates

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
    -o /out/portcullis \
    ./cmd/portcullis

# Final stage: distroless static, no shell.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /out/portcullis /usr/local/bin/portcullis

# Default configuration. The binary searches /etc/portcullis, so the container
# starts with the shipped defaults without any mounting.
COPY config.yaml.example /etc/portcullis/config.yaml

USER nonroot:nonroot

EXPOSE 8080 9090 8081

# distroless has no shell, so the healthcheck runs the subcommand directly.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/portcullis", "healthcheck", "--url", "http://127.0.0.1:8080/health"]

ENTRYPOINT ["/usr/local/bin/portcullis"]
CMD ["serve"]