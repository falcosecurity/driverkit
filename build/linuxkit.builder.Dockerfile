ARG KERNEL_VERSION

FROM linuxkit/kernel:${KERNEL_VERSION} AS src
FROM linuxkit/alpine:3fdc49366257e53276c6f363956a4353f95d9a81 AS builder

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

COPY --from=src /kernel-dev.tar /

RUN apk add --no-cache --update \
    build-base gcc bash curl tar xz clang llvm
