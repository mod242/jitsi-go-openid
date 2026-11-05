ARG GO_VERSION=1.27.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -ldflags "-w -s" -o jitsi-go-openid

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
COPY --from=build /src/jitsi-go-openid .
COPY LICENSE .

EXPOSE 3001

USER 1000

ENTRYPOINT ["./jitsi-go-openid"]
