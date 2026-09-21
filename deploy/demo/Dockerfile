# Builds every demo binary into one small image. The demo compose file runs the
# same image several times, selecting the command.
FROM golang:1.27-alpine AS builder

ARG VERSION=demo
ARG COMMIT=none

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN for cmd in portcullis mockjev trafficgen demo-upstream; do \
        CGO_ENABLED=0 go build -trimpath \
            -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT}" \
            -o /out/${cmd} ./cmd/${cmd}; \
    done

FROM alpine:3.24

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S demo && adduser -S demo -G demo

COPY --from=builder /out/portcullis /usr/local/bin/portcullis
COPY --from=builder /out/mockjev /usr/local/bin/mockjev
COPY --from=builder /out/trafficgen /usr/local/bin/trafficgen
COPY --from=builder /out/demo-upstream /usr/local/bin/demo-upstream

USER demo
WORKDIR /home/demo

# No ENTRYPOINT: the compose file picks a binary for each service.
CMD ["portcullis", "serve"]