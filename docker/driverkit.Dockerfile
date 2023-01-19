FROM docker.io/alpine:3.16

ARG TARGETARCH

COPY build-${TARGETARCH}/driverkit /bin/driverkit
CMD ["/bin/driverkit"]
