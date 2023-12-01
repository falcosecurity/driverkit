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
	make \
	git

# Install cmake3.x (on centos7 `cmake` package installs cmake2.x)
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v3.22.5/cmake-3.22.5-linux-$(uname -m).tar.gz; \
    gzip -d /tmp/cmake.tar.gz; \
    tar -xpf /tmp/cmake.tar --directory=/tmp; \
    cp -R /tmp/cmake-3.22.5-linux-$(uname -m)/* /usr; \
    rm -rf /tmp/cmake-3.22.5-linux-$(uname -m)/

# Properly create soft link
RUN ln -s /usr/bin/gcc /usr/bin/gcc-4.8.5

RUN source scl_source enable llvm-toolset-7.0
RUN echo "source scl_source enable llvm-toolset-7.0" >> /etc/bashrc
RUN source /etc/bashrc
