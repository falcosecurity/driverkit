FROM fedora:39

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG TARGETARCH
# Cmake version to install, in the form M.m.p.
ARG CMAKE_VERSION

RUN dnf install -y \
	bash-completion \
	bc \
	ca-certificates \
	curl \
	dkms \
	dwarves \
	gnupg2 \
	gcc \
	jq \
	glibc-devel \
	elfutils-libelf-devel \
	netcat \
	xz \
	cpio \
	flex \
	bison \
	openssl \
	openssl-devel \
	ncurses-devel \
	systemd-devel \
	pciutils-devel \
	binutils-devel \
	lsb-release \
	wget \
	gpg \
	zstd \
	git

# Install specific cmake version.
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz && \
    gzip -d /tmp/cmake.tar.gz && \
    tar -xpf /tmp/cmake.tar --directory=/tmp && \
    cp -R /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/* /usr && \
    rm -rf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/

# Properly create soft links
RUN ln -s /usr/bin/gcc /usr/bin/gcc-13.0.0
