FROM centos:7.9.2009

RUN yum update -y && \
	yum install -y gcc make curl libcurl elfutils-libelf-devel kmod && \
	ln -sf /usr/bin/gcc /usr/bin/gcc-4.9
