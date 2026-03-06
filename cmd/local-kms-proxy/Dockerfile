FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
WORKDIR /src/cmd/local-kms-proxy
RUN go build -o /local-kms-proxy .

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /local-kms-proxy /usr/local/bin/
ENTRYPOINT ["local-kms-proxy"]
