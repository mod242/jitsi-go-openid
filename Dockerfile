FROM registry.access.redhat.com/ubi9/go-toolset:latest as build
COPY . .

RUN go build -buildvcs=false -ldflags "-w -s" -o jitsi-go-openid

FROM registry.access.redhat.com/ubi9/ubi-minimal:latest
COPY --from=build /opt/app-root/src/jitsi-go-openid .
COPY LICENSE .

EXPOSE 3001

USER 1000

ENTRYPOINT ["./jitsi-go-openid"]
