FROM docker.io/golang:1.14-alpine3.11 as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache --update
RUN apk add gcc musl-dev make bash git
ADD . /driverkit

WORKDIR /driverkit

RUN make build

FROM docker.io/alpine:3.11
COPY --from=builder /driverkit/_output/bin/driverkit /bin/driverkit
CMD ["/bin/driverkit"]