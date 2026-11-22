FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath -ldflags "-s -w -X github.com/zyvorai/zyvor-setura-gateway/internal/setura.Version=${VERSION}" -o /setura ./cmd/setura

FROM gcr.io/distroless/static-debian12:nonroot
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="Zyvor Setura" \
      org.opencontainers.image.description="Publish and diagnose a local Envoy gateway" \
      org.opencontainers.image.source="https://github.com/zyvorai/zyvor-setura-gateway" \
      org.opencontainers.image.url="https://github.com/zyvorai/zyvor-setura-gateway" \
      org.opencontainers.image.licenses="LicenseRef-Zyvor-Production-1.0" \
      org.opencontainers.image.vendor="Zyvor AI Labs Private Limited" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /setura /setura
USER 65532:65532
ENTRYPOINT ["/setura"]
