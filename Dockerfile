FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X github.com/zyvorai/zyvor-setura-gateway/internal/setura.Version=${VERSION}" -o /setura ./cmd/setura

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /setura /setura
USER 65532:65532
ENTRYPOINT ["/setura"]
