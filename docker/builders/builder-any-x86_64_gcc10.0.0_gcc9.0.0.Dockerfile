FROM debian:bullseye

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG TARGETARCH

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
    && rm -rf /var/lib/apt/lists/*

# Properly create soft link
RUN ln -s /usr/bin/gcc-9 /usr/bin/gcc-9.0.0
RUN ln -s /usr/bin/gcc-10 /usr/bin/gcc-10.0.0