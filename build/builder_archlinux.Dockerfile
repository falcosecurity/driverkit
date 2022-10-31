# For building ArchLinux kernels requiring gcc-11 and gcc-12
# Arch Linux is a rolling release, the gcc versions and such will change over time
# pinned for now for gcc 11/12
FROM archlinux:base-20221030.0.98412

RUN pacman -Sy && pacman -Sy --noconfirm \
    make   \
    pahole \
    gcc11  \
    gcc && \
    ln -s /usr/bin/gcc /usr/bin/gcc-12