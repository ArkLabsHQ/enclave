FROM golang:1.25-alpine AS builder
WORKDIR /src
COPY . .
WORKDIR /src/cmd/mock-imds
RUN go build -o /mock-imds .

FROM alpine:latest
COPY --from=builder /mock-imds /usr/local/bin/
ENTRYPOINT ["mock-imds"]
