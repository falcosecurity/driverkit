FROM redhat/ubi8

RUN yum update -y && \
	yum install -y gcc curl make binutils kmod && \
	ln -sf /usr/bin/gcc /usr/bin/gcc-4.9
