ARG GO_VERSION=1.27.3
FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -ldflags "-w -s" -o jitsi-go-openid

FROM scratch
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=build /src/jitsi-go-openid .
COPY LICENSE .

EXPOSE 3001

USER 1000

ENTRYPOINT ["./jitsi-go-openid"]
