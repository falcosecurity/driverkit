FROM archlinux:base-devel-20250119.0.299327

LABEL maintainer="cncf-falco-dev@lists.cncf.io"

RUN pacman -Sy && pacman -Sy --noconfirm cmake pahole clang llvm git cpio wget openssl bc


# Properly create soft link
RUN ln -s /usr/bin/gcc /usr/bin/gcc-14.2.1
