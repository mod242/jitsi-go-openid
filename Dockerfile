FROM --platform=$BUILDPLATFORM registry.access.redhat.com/ubi9/go-toolset:latest AS build
ARG TARGETOS
ARG TARGETARCH
COPY . .

RUN GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -ldflags "-w -s" -o jitsi-go-openid

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
COPY --from=build /opt/app-root/src/jitsi-go-openid .
COPY LICENSE .

EXPOSE 3001

USER 1000

ENTRYPOINT ["./jitsi-go-openid"]
