FROM golang:1.27.2 AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

COPY . .
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg/mod \
    CGO_ENABLED=0 go build -buildvcs=false -o /build/ ./cmd/mc-router ./cmd/nethernet-router

FROM cgr.dev/chainguard/static
# The NetherNet DaemonSet runs this image with command: ["/nethernet-router"].
ENTRYPOINT ["/mc-router"]
COPY --from=builder /build/mc-router /mc-router
COPY --from=builder /build/nethernet-router /nethernet-router
