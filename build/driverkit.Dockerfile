FROM docker.io/golang:1.17-alpine3.16 as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache --update
RUN apk add gcc musl-dev make bash git go
ADD . /driverkit

WORKDIR /driverkit
RUN make build

FROM docker.io/alpine:3.16
COPY --from=builder /driverkit/_output/bin/driverkit /bin/driverkit
CMD ["/bin/driverkit"]