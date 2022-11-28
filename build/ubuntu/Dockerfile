FROM ubuntu:22.04
RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=America/US
RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
	dkms \
	gcc-11 \
	jq \
	libelf-dev \
	xz-utils \
	rpm2cpio \
	cpio \
	flex \
	bison \
	libpci-dev
RUN apt-get install -y --no-install-recommends \
	bc \
	curl \
	gnupg2 \
	ca-certificates \
	libiberty-dev \
	lsb-release \
	libc6-dev \
	libssl-dev \
	wget \
	gpg \
	zstd \
	openssl \
	libncurses-dev \
	libudev-dev
RUN apt-get install -y --no-install-recommends \
	golang-go \
	&& rm -rf /var/lib/apt/lists/*
RUN ln -sf /usr/bin/gcc-11 /usr/bin/gcc
RUN ln -sf /usr/bin/gcc-11 /usr/bin/gcc-4.9
WORKDIR /driverkit

