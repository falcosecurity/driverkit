FROM docker.io/golang:1.14-alpine3.11 as builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN apk add --no-cache --update
RUN apk add make bash git
ADD . /driverkit

WORKDIR /driverkit

RUN make build

FROM docker.io/alpine:3.11
# make and bash are often used to invoke driverkit itself, do not remove!
RUN apk add --no-cache --update && apk add make bash
COPY --from=builder /driverkit/_output/bin/driverkit /bin/driverkit
CMD ["/bin/driverkit"]


