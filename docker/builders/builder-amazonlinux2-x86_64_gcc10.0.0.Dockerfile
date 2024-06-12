FROM amazonlinux:2.0.20240529.0

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN yum -y install gcc10 \
    clang \
    llvm \
    bash-completion \
    bc \
    ca-certificates \
    curl \
    gnupg2 \
    libc6-dev \
    elfutils-libelf-devel \
    xz \
    cpio \
    flex \
    bison \
    openssl \
    openssl-devel \
    wget \
    binutils \
    which \
    make \
    cmake3 \
    tar \
    zstd \
    git

# Properly create soft links
RUN ln -s /usr/bin/gcc10-cc /usr/bin/gcc-10.0.0
RUN ln -s /usr/bin/cmake3 /usr/bin/cmake