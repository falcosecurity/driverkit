FROM fedora:41

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

ARG TARGETARCH

RUN dnf install -y \
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
	cmake \
	git

# Properly create soft links
RUN ln -s /usr/bin/gcc /usr/bin/gcc-14.0.0
