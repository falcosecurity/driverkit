FROM centos:7

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

# Cmake version to install, in the form M.m.p.
ARG CMAKE_VERSION

# Fix broken mirrors - centos:7 eol
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo; \
    sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo; \
    sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

RUN yum -y install centos-release-scl

# fix broken mirrors (again)
RUN sed -i s/mirror.centos.org/vault.centos.org/g /etc/yum.repos.d/*.repo; \
    sed -i s/^#.*baseurl=http/baseurl=https/g /etc/yum.repos.d/*.repo; \
    sed -i s/^mirrorlist=http/#mirrorlist=https/g /etc/yum.repos.d/*.repo

RUN yum -y install gcc \
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

# Install specific cmake version.
RUN curl -L -o /tmp/cmake.tar.gz https://github.com/Kitware/CMake/releases/download/v${CMAKE_VERSION}/cmake-${CMAKE_VERSION}-linux-$(uname -m).tar.gz && \
    gzip -d /tmp/cmake.tar.gz && \
    tar -xpf /tmp/cmake.tar --directory=/tmp && \
    cp -R /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/* /usr && \
    rm -rf /tmp/cmake-${CMAKE_VERSION}-linux-$(uname -m)/

# Properly create soft link
RUN ln -s /usr/bin/gcc /usr/bin/gcc-4.8.5

RUN source scl_source enable llvm-toolset-7.0
RUN echo "source scl_source enable llvm-toolset-7.0" >> /etc/bashrc
RUN source /etc/bashrc
