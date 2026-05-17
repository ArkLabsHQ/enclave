# awsmocks image — KMS-Decrypt-with-Recipient proxy on :4000 + IMDSv2
# stub on :1338, each with /health. Published as
# ghcr.io/arklabshq/enclave-awsmocks:<framework-version> by a manual
# maintainer push (see test/RELEASE.md).
#
# Build context is this directory (`awsmocks/`).
#   docker buildx build -f awsmocks/Dockerfile -t enclave-awsmocks:dev awsmocks/

FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -trimpath -o /awsmocks .

FROM alpine:latest
RUN apk add --no-cache ca-certificates wget
COPY --from=builder /awsmocks /usr/local/bin/
ENTRYPOINT ["awsmocks"]
