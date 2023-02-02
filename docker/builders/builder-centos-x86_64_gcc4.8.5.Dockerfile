FROM centos:7

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN yum -y install centos-release-scl && \
    yum -y install gcc \
    llvm-toolset-7.0 \
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
	make

# Properly create soft link
RUN ln -s /usr/bin/gcc /usr/bin/gcc-4.8.5

RUN source scl_source enable llvm-toolset-7.0
RUN echo "source scl_source enable llvm-toolset-7.0" >> /etc/bashrc
RUN source /etc/bashrc
