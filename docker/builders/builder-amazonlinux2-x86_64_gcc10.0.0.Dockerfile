FROM amazonlinux:2.0.20240529.0

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

# Cmake version to install, in the form M.m.p.
ARG CMAKE_VERSION

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
    tar \
    zstd \
    git

# Install specific cmake version.
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz && \
    gzip -d /tmp/cmake.tar.gz && \
    tar -xpf /tmp/cmake.tar --directory=/tmp && \
    cp -R /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/* /usr && \
    rm -rf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/

# Properly create soft links
RUN ln -s /usr/bin/gcc10-cc /usr/bin/gcc-10.0.0