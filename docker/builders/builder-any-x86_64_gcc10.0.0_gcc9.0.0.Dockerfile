FROM debian:bullseye

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG TARGETARCH
# Cmake version to install, in the form M.m.p.
ARG CMAKE_VERSION

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	bash-completion \
	bc \
	clang \
    llvm \
	ca-certificates \
	curl \
	dkms \
	dwarves \
	gnupg2 \
	gcc \
    gcc-9 \
	jq \
	libc6-dev \
	libelf-dev \
	netcat \
	xz-utils \
	rpm2cpio \
	cpio \
	flex \
	bison \
	openssl \
	libssl-dev \
	libncurses-dev \
	libudev-dev \
	libpci-dev \
	libiberty-dev \
	lsb-release \
	wget \
	software-properties-common \
	gpg \
	zstd \
	git \
	&& rm -rf /var/lib/apt/lists/*

# Install specific cmake version.
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/

# Properly create soft link
RUN ln -s /usr/bin/gcc-9 /usr/bin/gcc-9.0.0
RUN ln -s /usr/bin/gcc-10 /usr/bin/gcc-10.0.0
