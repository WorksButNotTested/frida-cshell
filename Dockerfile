################################################################################
# PLATFORM                                                                     #
################################################################################
FROM ubuntu:22.04 as platform
ARG http_proxy
ARG https_proxy

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
RUN echo "export http_proxy=$http_proxy" >> /etc/environment
RUN echo "export https_proxy=$https_proxy" >> /etc/environment

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install -y \
    wget \
    xz-utils \
    bzip2 \
    git \
    gcc \
    make \
    m4 \
    bc \
    cpio \
    patch \
    gawk \
    perl \
    texinfo \
    git \
    vim \
    less \
    qemu-system \
    flex \
    bison \
    libssl-dev \
    libc6-i386 \
    qemu-system-arm \
    gcc-multilib \
    libelf-dev \
    python3-dev \
    python3-pip \
    g++ \
    g++-multilib

RUN wget \
  -O /tmp/node.sh \
  https://deb.nodesource.com/setup_20.x
RUN bash /tmp/node.sh
RUN apt-get install -y nodejs

RUN wget \
    -O /tmp/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz \
    https://developer.arm.com/-/media/Files/downloads/gnu-a/10.3-2021.07/binrel/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz
RUN tar -C /opt -J -x -v -f /tmp/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu.tar.xz
ENV PATH=$PATH:/opt/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/bin/

RUN wget \
    -O /tmp/arm-gnu-toolchain-13.2.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz \
    https://developer.arm.com/-/media/Files/downloads/gnu/13.2.rel1/binrel/arm-gnu-toolchain-13.2.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz
RUN tar -C /opt -J -x -v -f /tmp/arm-gnu-toolchain-13.2.rel1-x86_64-arm-none-linux-gnueabihf.tar.xz
ENV PATH=$PATH:/opt/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-linux-gnueabihf/bin

################################################################################
# KERNEL-SOURCE                                                                #
################################################################################
FROM platform as kernel-source
WORKDIR /root/
RUN wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.8.7.tar.xz
RUN tar xf linux-6.8.7.tar.xz

################################################################################
# KERNEL-ARM32                                                                 #
################################################################################
FROM platform as kernel-arm32
COPY --from=kernel-source /root/linux-6.8.7 /root/linux-6.8.7
WORKDIR /root/linux-6.8.7

RUN mkdir build
RUN ARCH=arm make O=/root/linux-6.8.7/build/ defconfig

RUN echo "CONFIG_NET_9P=y" >> /root/linux-6.8.7/build/.config
RUN echo "CONFIG_NET_9P_FD=y" >> /root/linux-6.8.7/build/.config
RUN echo "CONFIG_NET_9P_VIRTIO=y" >> /root/linux-6.8.7/build/.config
RUN echo "CONFIG_9P_FS=y" >> /root/linux-6.8.7/build/.config

RUN ARCH=arm make O=/root/linux-6.8.7/build/ olddefconfig


WORKDIR /root/linux-6.8.7/build/

RUN ARCH=arm \
    CROSS_COMPILE=arm-none-linux-gnueabihf- \
    make \
        -j8 \
        zImage

################################################################################
# KERNEL-ARM64                                                                 #
################################################################################
FROM platform as kernel-arm64
COPY --from=kernel-source /root/linux-6.8.7 /root/linux-6.8.7
WORKDIR /root/linux-6.8.7

RUN mkdir build
RUN ARCH=arm64 make O=/root/linux-6.8.7/build/ defconfig
RUN echo "CONFIG_COMPAT=y" >> /root/linux-6.8.7/build/.config

WORKDIR /root/linux-6.8.7/build/

RUN ARCH=arm64 \
    CROSS_COMPILE=aarch64-none-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    make \
        -j8 \
        Image.gz

################################################################################
# KERNEL-x86                                                                   #
################################################################################
FROM platform as kernel-x86
COPY --from=kernel-source /root/linux-6.8.7 /root/linux-6.8.7
WORKDIR /root/linux-6.8.7

RUN mkdir build
RUN ARCH=i386 make O=/root/linux-6.8.7/build/ defconfig

WORKDIR /root/linux-6.8.7/build/

RUN ARCH=i386 \
    make \
        -j8 \
        bzImage

################################################################################
# KERNEL-x64                                                                   #
################################################################################
FROM platform as kernel-x64
COPY --from=kernel-source /root/linux-6.8.7 /root/linux-6.8.7
WORKDIR /root/linux-6.8.7

RUN mkdir build
RUN make O=/root/linux-6.8.7/build/ defconfig

WORKDIR /root/linux-6.8.7/build/

RUN make \
        -j8 \
        bzImage

################################################################################
# BUSYBOX SOURCE                                                               #
################################################################################
FROM platform as busybox-source
RUN wget \
    -O /tmp/busybox-1.36.1.tar.bz2 \
    https://busybox.net/downloads/busybox-1.36.1.tar.bz2

RUN tar -C /root/ -j -x -v -f /tmp/busybox-1.36.1.tar.bz2

################################################################################
# BUSYBOX-ARM32                                                                #
################################################################################
FROM platform as busybox-arm32
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=arm-none-linux-gnueabihf- \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=arm-none-linux-gnueabihf- \
    -j8 \
    install

################################################################################
# BUSYBOX-ARM64                                                                #
################################################################################
FROM platform as busybox-arm64
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=aarch64-none-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=aarch64-none-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    -j8 \
    install

################################################################################
# BUSYBOX-x86                                                                  #
################################################################################
FROM platform as busybox-x86
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    CFLAGS="-m32 -march=i386" \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    CFLAGS="-m32 -march=i386" \
    LDFLAGS="-m32" \
    -j8 \
    install

################################################################################
# BUSYBOX-x64                                                                  #
################################################################################
FROM platform as busybox-x64
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    -j8 \
    install

################################################################################
# TARGET                                                                       #
################################################################################
FROM platform as target
COPY assets/target/target.c /root/target.c
COPY assets/target/module.c /root/module.c
RUN mkdir /root/x64
WORKDIR /root/x64
RUN gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -o module.so \
    /root/module.c
RUN gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -o target \
    /root/target.c
RUN mkdir /root/x86
WORKDIR /root/x86
RUN gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -m32 \
    -o module.so \
    /root/module.c
RUN gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -m32 \
    -o target \
    /root/target.c
RUN mkdir /root/arm
WORKDIR /root/arm
RUN arm-none-linux-gnueabihf-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -o module.so \
    /root/module.c
RUN arm-none-linux-gnueabihf-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -o target \
    /root/target.c
RUN mkdir /root/arm64
WORKDIR /root/arm64
RUN aarch64-none-linux-gnu-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -march=armv8-a \
    -o module.so \
    /root/module.c
RUN aarch64-none-linux-gnu-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -march=armv8-a \
    -o target \
    /root/target.c

################################################################################
# FRIDA SOURCE                                                                 #
################################################################################
FROM platform as frida-source
WORKDIR /root/
ENV TAG=cf590d7
RUN git clone \
    -b 32bit-fix \
    https://github.com/WorksButNotTested/frida-core.git

################################################################################
# FRIDA-arm32                                                                  #
################################################################################
FROM platform as frida-arm32
COPY --from=frida-source /root/frida-core /root/frida-core
WORKDIR /root/frida-core
RUN CC=arm-none-linux-gnueabihf-gcc \
    CXX=arm-none-linux-gnueabihf-g++ \
    STRIP=arm-none-linux-gnueabihf-strip \
    NM=arm-none-linux-gnueabihf-nm \
    READELF=arm-none-linux-gnueabihf-readelf \
    ./configure \
        --host linux-armhf
RUN make

################################################################################
# FRIDA-arm64                                                                  #
################################################################################
FROM platform as frida-arm64
COPY --from=frida-source /root/frida-core /root/frida-core
WORKDIR /root/frida-core
RUN CC=aarch64-none-linux-gnu-gcc \
    CXX=aarch64-none-linux-gnu-g++ \
    STRIP=aarch64-none-linux-gnu-strip \
    NM=aarch64-none-linux-gnu-nm \
    READELF=aarch64-none-linux-gnu-readelf \
    ./configure \
        --host linux-arm64
RUN make

################################################################################
# FRIDA-x86                                                                    #
################################################################################
FROM platform as frida-x86
COPY --from=frida-source /root/frida-core /root/frida-core
WORKDIR /root/frida-core
RUN ./configure --host linux-x86
RUN make

################################################################################
# FRIDA-x64                                                                    #
################################################################################
FROM platform as frida-x64
COPY --from=frida-source /root/frida-core /root/frida-core
WORKDIR /root/frida-core
RUN ./configure --host linux-x86_64
RUN make

################################################################################
# INITRD-BASE                                                                  #
################################################################################
FROM platform as initrd-base
WORKDIR /root/
RUN mkdir /root/initramfs/
WORKDIR /root/initramfs/
RUN mkdir /root/initramfs/devtmpfs/
RUN mkdir -p /root/initramfs/home/share
RUN mkdir -p /root/initramfs/home/ws
RUN mkdir /root/initramfs/proc/
RUN mkdir /root/initramfs/root/
RUN mkdir /root/initramfs/sys/
RUN mkdir /root/initramfs/tmp/
RUN mkdir /root/initramfs/var/
RUN mkdir /root/initramfs/var/log/
RUN touch /root/initramfs/var/log/lastlog
COPY assets/initrd/group /root/initramfs/etc/group
COPY assets/initrd/passwd /root/initramfs/etc/passwd
COPY assets/initrd/motd /root/initramfs/etc/motd
COPY assets/initrd/.profile /root/initramfs/.profile
COPY assets/initrd/.cshellrc /root/initramfs/.cshellrc
COPY assets/initrd/entropy.c /root/entropy.c

################################################################################
# INITRD-ARM32                                                                 #
################################################################################
FROM initrd-base as initrd-arm32
COPY --from=busybox-arm32 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-arm32 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-arm32 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-arm32 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN arm-none-linux-gnueabihf-gcc \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN cp -av /opt/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-linux-gnueabihf/arm-none-linux-gnueabihf/libc/lib/ /root/initramfs/
COPY --from=frida-arm32 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-32
COPY --from=target /root/arm/target /root/initramfs/bin/target32
COPY --from=target /root/arm/module.so /root/initramfs/bin/module32.so
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-arm32 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-arm32.img

################################################################################
# INITRD-ARM64                                                                 #
################################################################################
FROM initrd-base as initrd-arm64
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN aarch64-none-linux-gnu-gcc \
    -march=armv8-a \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN cp -av /opt/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/aarch64-none-linux-gnu/libc/lib64 /root/initramfs/
RUN cp -av /opt/gcc-arm-10.3-2021.07-x86_64-aarch64-none-linux-gnu/aarch64-none-linux-gnu/libc/lib /root/initramfs/
RUN cp -av /opt/arm-gnu-toolchain-13.2.Rel1-x86_64-arm-none-linux-gnueabihf/arm-none-linux-gnueabihf/libc/lib/ /root/initramfs/
COPY --from=frida-arm64 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-64
COPY --from=frida-arm32 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-32
COPY --from=target /root/arm64/target /root/initramfs/bin/target64
COPY --from=target /root/arm64/module.so /root/initramfs/bin/module64.so
COPY --from=target /root/arm/target /root/initramfs/bin/target32
COPY --from=target /root/arm/module.so /root/initramfs/bin/module32.so
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-arm64 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-arm64.img

################################################################################
# INITRD-x86                                                                   #
################################################################################
FROM initrd-base as initrd-x86
COPY --from=busybox-x86 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-x86 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-x86 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-x86 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN gcc \
    -m32 \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN mkdir /root/initramfs/lib32/
RUN cp /lib32/ld-linux.so.2 /root/initramfs/lib32/ld-linux.so.2
RUN cp /lib32/libdl.so.2 /root/initramfs/lib32/libdl.so.2
RUN cp /lib32/libm.so.6 /root/initramfs/lib32/libm.so.6
RUN cp /lib32/librt.so.1 /root/initramfs/lib32/librt.so.1
RUN cp /lib32/libpthread.so.0 /root/initramfs/lib32/libpthread.so.0
RUN cp /lib32/libc.so.6 /root/initramfs/lib32/libc.so.6
RUN mkdir /root/initramfs/lib/
RUN ln -s /lib32/ld-linux.so.2 /root/initramfs/lib/ld-linux.so.2
COPY --from=frida-x86 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-32
COPY --from=target /root/x86/target /root/initramfs/bin/target32
COPY --from=target /root/x86/module.so /root/initramfs/bin/module32.so
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-x86 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-x86.img

################################################################################
# INITRD-x64                                                                   #
################################################################################
FROM initrd-base as initrd-x64
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN gcc \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN mkdir /root/initramfs/lib/
RUN cp /lib64/ld-linux-x86-64.so.2 /root/initramfs/lib/ld-linux-x86-64.so.2
RUN cp /lib/x86_64-linux-gnu/libdl.so.2 /root/initramfs/lib/libdl.so.2
RUN cp /lib/x86_64-linux-gnu/libm.so.6 /root/initramfs/lib/libm.so.6
RUN cp /lib/x86_64-linux-gnu/librt.so.1 /root/initramfs/lib/librt.so.1
RUN cp /lib/x86_64-linux-gnu/libpthread.so.0 /root/initramfs/lib/libpthread.so.0
RUN cp /lib/x86_64-linux-gnu/libc.so.6 /root/initramfs/lib/libc.so.6
RUN mkdir /root/initramfs/lib64/
RUN ln -s /lib/ld-linux-x86-64.so.2 /root/initramfs/lib64/ld-linux-x86-64.so.2
RUN mkdir /root/initramfs/lib32/
RUN cp /lib32/ld-linux.so.2 /root/initramfs/lib32/ld-linux.so.2
RUN cp /lib32/libdl.so.2 /root/initramfs/lib32/libdl.so.2
RUN cp /lib32/libm.so.6 /root/initramfs/lib32/libm.so.6
RUN cp /lib32/librt.so.1 /root/initramfs/lib32/librt.so.1
RUN cp /lib32/libpthread.so.0 /root/initramfs/lib32/libpthread.so.0
RUN cp /lib32/libc.so.6 /root/initramfs/lib32/libc.so.6
RUN ln -s /lib32/ld-linux.so.2 /root/initramfs/lib/ld-linux.so.2
COPY --from=frida-x64 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-64
COPY --from=frida-x86 /root/frida-core/build/inject/frida-inject /root/initramfs/bin/frida-inject-32
COPY --from=target /root/x64/target /root/initramfs/bin/target64
COPY --from=target /root/x64/module.so /root/initramfs/bin/module64.so
COPY --from=target /root/x86/target /root/initramfs/bin/target32
COPY --from=target /root/x86/module.so /root/initramfs/bin/module32.so
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-x64 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-x64.img

################################################################################
# CSHELL                                                                       #
################################################################################
FROM platform as cshell
COPY --from=kernel-arm32 /root/linux-6.8.7/build/arch/arm/boot/zImage /root/zImage-arm32
COPY --from=kernel-arm64 /root/linux-6.8.7/build/arch/arm64/boot/Image.gz /root/zImage-arm64
COPY --from=kernel-x64 /root/linux-6.8.7/build/arch/x86_64/boot/bzImage /root/bzImage-x64
COPY --from=kernel-x86 /root/linux-6.8.7/build/arch/i386/boot/bzImage /root/bzImage-x86
COPY --from=initrd-arm32 /root/initramfs-arm32.img /root/initramfs-arm32.img
COPY --from=initrd-arm64 /root/initramfs-arm64.img /root/initramfs-arm64.img
COPY --from=initrd-x64 /root/initramfs-x64.img /root/initramfs-x64.img
COPY --from=initrd-x86 /root/initramfs-x86.img /root/initramfs-x86.img
RUN mkdir /home/ws/
COPY --from=frida-x64 /root/frida-core/build/inject/frida-inject /usr/bin/frida-inject-64
COPY --from=frida-x86 /root/frida-core/build/inject/frida-inject /usr/bin/frida-inject-32
COPY --from=target /root/x64/target /usr/bin/target64
COPY --from=target /root/x64/module.so /usr/bin/module64.so
COPY --from=target /root/x86/target /usr/bin/target32
COPY --from=target /root/x86/module.so /usr/bin/module32.so
COPY assets/cshell/test.js /root/
COPY assets/cshell/vm-arm32 /bin/vm-arm32
COPY assets/cshell/vm-arm64 /bin/vm-arm64
COPY assets/cshell/vm-x64 /bin/vm-x64
COPY assets/cshell/vm-x86 /bin/vm-x86
WORKDIR /root/

################################################################################
# CSHELL-ARM32                                                                 #
################################################################################
FROM cshell as cshell-arm32
ENTRYPOINT ["/bin/vm-arm32"]

################################################################################
# CSHELL-ARM64                                                                 #
################################################################################
FROM cshell as cshell-arm64
ENTRYPOINT ["/bin/vm-arm64"]

################################################################################
# CSHELL-x86                                                                   #
################################################################################
FROM cshell as cshell-x86
ENTRYPOINT ["/bin/vm-x86"]

################################################################################
# CSHELL-x64                                                                   #
################################################################################
FROM cshell as cshell-x64
ENTRYPOINT ["/bin/vm-x64"]
