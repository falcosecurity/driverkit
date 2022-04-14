FROM debian:buster

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN cp /etc/skel/.bashrc /root && cp /etc/skel/.profile /root

RUN apt-get update \
	&& apt-get install -y --no-install-recommends \
	bash-completion \
	bc \
	clang-7 \
	ca-certificates \
	curl \
	dkms \
	gnupg2 \
	gcc \
	jq \
	libc6-dev \
	libelf-dev \
	libmpx2 \
	llvm-7 \
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
	gpg

# Install clang 12
RUN cd /tmp \
	&& wget https://apt.llvm.org/llvm.sh \
	&& chmod +x llvm.sh \
	&& ./llvm.sh 12

# gcc 6 is no longer included in debian stable, but we need it to
# build kernel modules on the default debian-based ami used by
# kops. So grab copies we've saved from debian snapshots with the
# prefix https://snapshot.debian.org/archive/debian/20170517T033514Z
# or so.

RUN curl -L -o cpp-6_6.3.0-18_amd64.deb https://download.falco.org/dependencies/cpp-6_6.3.0-18_amd64.deb \
	&& curl -L -o gcc-6-base_6.3.0-18_amd64.deb https://download.falco.org/dependencies/gcc-6-base_6.3.0-18_amd64.deb \
	&& curl -L -o gcc-6_6.3.0-18_amd64.deb https://download.falco.org/dependencies/gcc-6_6.3.0-18_amd64.deb \
	&& curl -L -o libasan3_6.3.0-18_amd64.deb https://download.falco.org/dependencies/libasan3_6.3.0-18_amd64.deb \
	&& curl -L -o libcilkrts5_6.3.0-18_amd64.deb https://download.falco.org/dependencies/libcilkrts5_6.3.0-18_amd64.deb \
	&& curl -L -o libgcc-6-dev_6.3.0-18_amd64.deb https://download.falco.org/dependencies/libgcc-6-dev_6.3.0-18_amd64.deb \
	&& curl -L -o libubsan0_6.3.0-18_amd64.deb https://download.falco.org/dependencies/libubsan0_6.3.0-18_amd64.deb \
	&& curl -L -o libmpfr4_3.1.3-2_amd64.deb https://download.falco.org/dependencies/libmpfr4_3.1.3-2_amd64.deb \
	&& curl -L -o libisl15_0.18-1_amd64.deb https://download.falco.org/dependencies/libisl15_0.18-1_amd64.deb \
	&& dpkg -i cpp-6_6.3.0-18_amd64.deb gcc-6-base_6.3.0-18_amd64.deb gcc-6_6.3.0-18_amd64.deb libasan3_6.3.0-18_amd64.deb libcilkrts5_6.3.0-18_amd64.deb libgcc-6-dev_6.3.0-18_amd64.deb libubsan0_6.3.0-18_amd64.deb libmpfr4_3.1.3-2_amd64.deb libisl15_0.18-1_amd64.deb \
	&& rm -f cpp-6_6.3.0-18_amd64.deb gcc-6-base_6.3.0-18_amd64.deb gcc-6_6.3.0-18_amd64.deb libasan3_6.3.0-18_amd64.deb libcilkrts5_6.3.0-18_amd64.deb libgcc-6-dev_6.3.0-18_amd64.deb libubsan0_6.3.0-18_amd64.deb libmpfr4_3.1.3-2_amd64.deb libisl15_0.18-1_amd64.deb

# gcc 5 is no longer included in debian stable, but we need it to
# build centos kernels, which are 3.x based and explicitly want a gcc
# version 3, 4, or 5 compiler. So grab copies we've saved from debian
# snapshots with the prefix https://snapshot.debian.org/archive/debian/20190122T000000Z.

RUN curl -L -o cpp-5_5.5.0-12_amd64.deb https://download.falco.org/dependencies/cpp-5_5.5.0-12_amd64.deb \
	&& curl -L -o gcc-5-base_5.5.0-12_amd64.deb https://download.falco.org/dependencies/gcc-5-base_5.5.0-12_amd64.deb \
	&& curl -L -o gcc-5_5.5.0-12_amd64.deb https://download.falco.org/dependencies/gcc-5_5.5.0-12_amd64.deb \
	&& curl -L -o libasan2_5.5.0-12_amd64.deb	https://download.falco.org/dependencies/libasan2_5.5.0-12_amd64.deb \
	&& curl -L -o libgcc-5-dev_5.5.0-12_amd64.deb https://download.falco.org/dependencies/libgcc-5-dev_5.5.0-12_amd64.deb \
	&& curl -L -o libisl15_0.18-4_amd64.deb https://download.falco.org/dependencies/libisl15_0.18-4_amd64.deb \
	&& curl -L -o libmpx0_5.5.0-12_amd64.deb https://download.falco.org/dependencies/libmpx0_5.5.0-12_amd64.deb \
	&& dpkg -i cpp-5_5.5.0-12_amd64.deb gcc-5-base_5.5.0-12_amd64.deb gcc-5_5.5.0-12_amd64.deb libasan2_5.5.0-12_amd64.deb libgcc-5-dev_5.5.0-12_amd64.deb libisl15_0.18-4_amd64.deb libmpx0_5.5.0-12_amd64.deb \
	&& rm -f cpp-5_5.5.0-12_amd64.deb gcc-5-base_5.5.0-12_amd64.deb gcc-5_5.5.0-12_amd64.deb libasan2_5.5.0-12_amd64.deb libgcc-5-dev_5.5.0-12_amd64.deb libisl15_0.18-4_amd64.deb libmpx0_5.5.0-12_amd64.deb

# gcc 4 is no longer included in debian stable, but we need it to
# build centos kernels, which are 2.x based and explicitly want a gcc
# version 4 compiler. So grab copies we've saved from debian
# snapshots with the prefix http://ftp.debian.org/debian/pool/main/g/gcc-4.8/.

RUN curl -L -o cpp-4.8_4.8.4-1_amd64.deb https://download.falco.org/dependencies/cpp-4.8_4.8.4-1_amd64.deb \
	&& curl -L -o gcc-4.8-base_4.8.4-1_amd64.deb https://download.falco.org/dependencies/gcc-4.8-base_4.8.4-1_amd64.deb \
	&& curl -L -o gcc-4.8_4.8.4-1_amd64.deb https://download.falco.org/dependencies/gcc-4.8_4.8.4-1_amd64.deb \
	&& curl -L -o libasan0_4.8.4-1_amd64.deb https://download.falco.org/dependencies/libasan0_4.8.4-1_amd64.deb \
	&& curl -L -o libgcc-4.8-dev_4.8.4-1_amd64.deb https://download.falco.org/dependencies/libgcc-4.8-dev_4.8.4-1_amd64.deb \
	&& curl -L -o libisl10_0.12.2-2_amd64.deb https://download.falco.org/dependencies/libisl10_0.12.2-2_amd64.deb \
	&& curl -L -o multiarch-support_2.19-18+deb8u10_amd64.deb https://download.falco.org/dependencies/multiarch-support_2.19-18%2Bdeb8u10_amd64.deb \
	&& curl -L -o libcloog-isl4_0.18.4-1+b1_amd64.deb https://download.falco.org/dependencies/libcloog-isl4_0.18.4-1%2Bb1_amd64.deb \
	&& dpkg -i multiarch-support_2.19-18+deb8u10_amd64.deb \
	&& dpkg -i libisl10_0.12.2-2_amd64.deb gcc-4.8-base_4.8.4-1_amd64.deb libasan0_4.8.4-1_amd64.deb libgcc-4.8-dev_4.8.4-1_amd64.deb libcloog-isl4_0.18.4-1+b1_amd64.deb cpp-4.8_4.8.4-1_amd64.deb gcc-4.8_4.8.4-1_amd64.deb \
	&& rm -f multiarch-support_2.19-18+deb8u10_amd64.deb libisl10_0.12.2-2_amd64.deb gcc-4.8-base_4.8.4-1_amd64.deb libasan0_4.8.4-1_amd64.deb libgcc-4.8-dev_4.8.4-1_amd64.deb libcloog-isl4_0.18.4-1+b1_amd64.deb cpp-4.8_4.8.4-1_amd64.deb gcc-4.8_4.8.4-1_amd64.deb

# debian:stable head contains binutils 2.31, which generates
# binaries that are incompatible with kernels < 4.16. So manually
# forcibly install binutils 2.30-22 instead.
RUN curl -L -o binutils_2.37-7_amd64.deb https://download.falco.org/dependencies/binutils_2.37-7_amd64.deb \
	&& curl -L -o libbinutils_2.37-7_amd64.deb https://download.falco.org/dependencies/libbinutils_2.37-7_amd64.deb \
	&& curl -L -o binutils-x86-64-linux-gnu_2.37-7_amd64.deb https://download.falco.org/dependencies/binutils-x86-64-linux-gnu_2.37-7_amd64.deb \
	&& curl -L -o binutils-common_2.37-7_amd64.deb https://download.falco.org/dependencies/binutils-common_2.37-7_amd64.deb \
	&& dpkg -i *binutils*.deb \
	&& rm -f *binutils*.deb

# zstd requires binutils >= 2.31.1 installed above.
RUN apt-get install -y --no-install-recommends zstd \
	&& rm -rf /var/lib/apt/lists/*
