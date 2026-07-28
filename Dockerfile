# ---- build ----------------------------------------------------------------
FROM golang:1.23-alpine AS build

ARG VERSION=dev
ARG COMMIT=none
ARG BUILT=unknown

WORKDIR /src
COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src/ ./
RUN CGO_ENABLED=0 GOOS=linux go build \
      -trimpath \
      -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.built=${BUILT}" \
      -o /aegis .

# ---- runtime --------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /aegis /aegis

# aegis writes nothing to disk. Run the container read-only.
USER nonroot:nonroot
EXPOSE 2019

ENV AEGIS_CONFIG=/etc/aegis/config.yaml \
    AEGIS_LISTEN=:2019

ENTRYPOINT ["/aegis"]
