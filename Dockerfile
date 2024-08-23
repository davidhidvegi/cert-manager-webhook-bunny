FROM --platform=$BUILDPLATFORM golang:1.23 AS build
WORKDIR /workspace
COPY go.mod go.sum .
RUN go mod download
COPY . .
ARG TARGETOS TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -o webhook -ldflags '-w -extldflags "-static"' .

FROM alpine:latest AS certs
RUN apk add -U --no-cache ca-certificates

FROM busybox:1.36.1-glibc
COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=build /workspace/webhook /usr/local/bin/webhook
ENTRYPOINT ["webhook"]
