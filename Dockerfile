################################################################################
# PLATFORM                                                                     #
################################################################################
FROM ubuntu:24.04 AS platform
ARG http_proxy
ARG https_proxy

ENV http_proxy=$http_proxy
ENV https_proxy=$https_proxy
RUN echo "export http_proxy=$http_proxy" >> /etc/environment
RUN echo "export https_proxy=$https_proxy" >> /etc/environment

ENV DEBIAN_FRONTEND=noninteractive
RUN dpkg --add-architecture i386
RUN apt-get update && \
    apt-get install -y \
    bc \
    bison \
    bzip2 \
    cmake \
    cpio \
    flex \
    g++ \
    g++-aarch64-linux-gnu \
    g++-arm-linux-gnueabihf \
    g++-i686-linux-gnu \
    gcc \
    gcc-aarch64-linux-gnu \
    gcc-arm-linux-gnueabihf \
    gcc-i686-linux-gnu \
    gawk \
    gcc \
    git \
    git \
    less \
    libc6-dev:i386 \
    libelf-dev \
    libgcc-12-dev:i386 \
    libssl-dev \
    m4 \
    make \
    patch \
    perl \
    python3-dev \
    python3-pip \
    qemu-system \
    qemu-system-arm \
    texinfo \
    vim \
    wget \
    xz-utils

RUN wget \
  -O /tmp/node.sh \
  https://deb.nodesource.com/setup_20.x
RUN bash /tmp/node.sh
RUN apt-get install -y nodejs

################################################################################
# KERNEL-SOURCE                                                                #
################################################################################
FROM platform AS kernel-source
WORKDIR /root/
RUN wget https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.15.2.tar.xz
RUN tar xf linux-6.15.2.tar.xz

################################################################################
# KERNEL-ARM64                                                                 #
################################################################################
FROM platform AS kernel-arm64
COPY --from=kernel-source /root/linux-6.15.2 /root/linux-6.15.2
WORKDIR /root/linux-6.15.2

RUN mkdir build
RUN ARCH=arm64 make O=/root/linux-6.15.2/build/ defconfig
RUN echo "CONFIG_COMPAT=y" >> /root/linux-6.15.2/build/.config

WORKDIR /root/linux-6.15.2/build/

RUN ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    make \
        -j8 \
        Image.gz && \
    cp /root/linux-6.15.2/build/arch/arm64/boot/Image.gz /root/zImage-arm64 \
    && rm -rf /root/linux-6.15.2

################################################################################
# KERNEL-ARM64BE                                                               #
################################################################################
FROM platform AS kernel-arm64be
COPY --from=ghcr.io/frida/x-tools-linux-be-target /root/Image.gz /root/zImage-arm64be

################################################################################
# KERNEL-x64                                                                   #
################################################################################
FROM platform AS kernel-x64
COPY --from=kernel-source /root/linux-6.15.2 /root/linux-6.15.2
WORKDIR /root/linux-6.15.2

RUN mkdir build
RUN make O=/root/linux-6.15.2/build/ defconfig

WORKDIR /root/linux-6.15.2/build/

RUN make \
        -j8 \
        bzImage && \
    cp /root/linux-6.15.2/build/arch/x86_64/boot/bzImage /root/bzImage-x64 \
    && rm -rf /root/linux-6.15.2

################################################################################
# BUSYBOX SOURCE                                                               #
################################################################################
FROM platform AS busybox-source
RUN wget \
    -O /tmp/busybox-1.36.1.tar.bz2 \
    https://busybox.net/downloads/busybox-1.36.1.tar.bz2

RUN tar -C /root/ -j -x -v -f /tmp/busybox-1.36.1.tar.bz2

################################################################################
# BUSYBOX-ARM64                                                                #
################################################################################
FROM platform AS busybox-arm64
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config
RUN sed -i "s/CONFIG_TC=y/CONFIG_TC=n/g" /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CFLAGS="-march=armv8-a" \
    -j8 \
    install

################################################################################
# BUSYBOX-x64                                                                  #
################################################################################
FROM platform AS busybox-x64
COPY --from=busybox-source /root/busybox-1.36.1 /root/busybox-1.36.1
WORKDIR /root/busybox-1.36.1
RUN mkdir build

RUN make \
    O=/root/busybox-1.36.1/build \
    defconfig

RUN echo "CONFIG_STATIC=y" >> /root/busybox-1.36.1/build/.config
RUN sed -i "s/CONFIG_TC=y/CONFIG_TC=n/g" /root/busybox-1.36.1/build/.config

RUN make \
    O=/root/busybox-1.36.1/build \
    -j8 \
    install

################################################################################
# INITRD-BASE                                                                  #
################################################################################
FROM platform AS initrd-base
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
# INITRD-ARM64                                                                 #
################################################################################
FROM initrd-base AS initrd-arm64
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-arm64 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN aarch64-linux-gnu-gcc \
    -march=armv8-a \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN cp -av /usr/arm-linux-gnueabihf/lib/ /root/initramfs/lib
RUN cp -av /usr/aarch64-linux-gnu/lib/ /root/initramfs/lib64
RUN ln -s /lib64/ld-linux-aarch64.so.1 /root/initramfs/lib/ld-linux-aarch64.so.1
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-arm64.xz | xz -d > /root/initramfs/bin/frida-inject-64
RUN chmod +x /root/initramfs/bin/frida-inject-64
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-armhf.xz | xz -d > /root/initramfs/bin/frida-inject-32
RUN chmod +x /root/initramfs/bin/frida-inject-32
COPY assets/target/target.c /root/target.c
COPY assets/target/module.c /root/module.c
RUN aarch64-linux-gnu-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -march=armv8-a \
    -o /root/initramfs/bin/module64.so \
    /root/module.c
RUN aarch64-linux-gnu-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -march=armv8-a \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target64 \
    /root/target.c
RUN arm-linux-gnueabihf-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -marm \
    -o /root/initramfs/bin/module32.so \
    /root/module.c
RUN arm-linux-gnueabihf-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -marm \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target32 \
    /root/target.c    
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-arm64 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-arm64.img

################################################################################
# INITRD-ARM64BE                                                               #
################################################################################
FROM platform AS initrd-arm64be
COPY --from=ghcr.io/frida/x-tools-linux-be-target /root/initramfs.img /root/initramfs.img
COPY --from=ghcr.io/frida/x-tools-linux-armbe8 /opt/x-tools /opt/x-tools
COPY --from=ghcr.io/frida/x-tools-linux-arm64be /opt/x-tools /opt/x-tools
ENV PATH="/opt/x-tools/armeb-linux-gnueabi/bin:$PATH"
ENV PATH="/opt/x-tools/aarch64_be-linux-gnu/bin:$PATH"
RUN mkdir /root/initramfs/
WORKDIR /root/initramfs/
RUN cat /root/initramfs.img | cpio --extract
RUN mkdir -p /root/initramfs/home/ws
COPY assets/initrd/group /root/initramfs/etc/group
COPY assets/initrd/passwd /root/initramfs/etc/passwd
COPY assets/initrd/motd /root/initramfs/etc/motd
COPY assets/initrd/.profile /root/initramfs/.profile
COPY assets/initrd/.cshellrc /root/initramfs/.cshellrc
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-arm64be.xz | xz -d > /root/initramfs/bin/frida-inject-64
RUN chmod +x /root/initramfs/bin/frida-inject-64
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-armbe8.xz | xz -d > /root/initramfs/bin/frida-inject-32
RUN chmod +x /root/initramfs/bin/frida-inject-32
COPY assets/target/target.c /root/target.c
COPY assets/target/module.c /root/module.c
RUN aarch64_be-linux-gnu-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -march=armv8-a \
    -o /root/initramfs/bin/module64.so \
    /root/module.c
RUN aarch64_be-linux-gnu-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -march=armv8-a \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target64 \
    /root/target.c
RUN armeb-linux-gnueabi-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -marm \
    -o /root/initramfs/bin/module32.so \
    /root/module.c
RUN armeb-linux-gnueabi-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -marm \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target32 \
    /root/target.c    
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-arm64be /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-arm64be.img

################################################################################
# INITRD-x64                                                                   #
################################################################################
FROM initrd-base AS initrd-x64
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/bin /root/initramfs/bin/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/sbin /root/initramfs/sbin/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/usr /root/initramfs/usr/
COPY --from=busybox-x64 /root/busybox-1.36.1/build/_install/linuxrc /root/initramfs/linuxrc
RUN gcc \
    -static \
    -o /root/initramfs/sbin/entropy \
    /root/entropy.c
RUN mkdir /root/initramfs/lib64/
RUN cp /lib64/ld-linux-x86-64.so.2 /root/initramfs/lib64/ld-linux-x86-64.so.2
RUN cp /lib/x86_64-linux-gnu/libdl.so.2 /root/initramfs/lib64/libdl.so.2
RUN cp /lib/x86_64-linux-gnu/libm.so.6 /root/initramfs/lib64/libm.so.6
RUN cp /lib/x86_64-linux-gnu/librt.so.1 /root/initramfs/lib64/librt.so.1
RUN cp /lib/x86_64-linux-gnu/libpthread.so.0 /root/initramfs/lib64/libpthread.so.0
RUN cp /lib/x86_64-linux-gnu/libc.so.6 /root/initramfs/lib64/libc.so.6
RUN mkdir /root/initramfs/lib/
RUN cp /usr/i686-linux-gnu/lib/ld-linux.so.2 /root/initramfs/lib/ld-linux.so.2
RUN cp /usr/i686-linux-gnu/lib/libdl.so.2 /root/initramfs/lib/libdl.so.2
RUN cp /usr/i686-linux-gnu/lib/libm.so.6 /root/initramfs/lib/libm.so.6
RUN cp /usr/i686-linux-gnu/lib/librt.so.1 /root/initramfs/lib/librt.so.1
RUN cp /usr/i686-linux-gnu/lib/libpthread.so.0 /root/initramfs/lib/libpthread.so.0
RUN cp /usr/i686-linux-gnu/lib/libc.so.6 /root/initramfs/lib/libc.so.6
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-x86_64.xz | xz -d > /root/initramfs/bin/frida-inject-64
RUN chmod +x /root/initramfs/bin/frida-inject-64
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-x86.xz | xz -d > /root/initramfs/bin/frida-inject-32
RUN chmod +x /root/initramfs/bin/frida-inject-32
COPY assets/target/target.c /root/target.c
COPY assets/target/module.c /root/module.c
RUN gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \
    -o /root/initramfs/bin/module64.so \
    /root/module.c
RUN gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target64 \
    /root/target.c
RUN i686-linux-gnu-gcc \
    -Wall \
    -Werror \
    -no-pie \
    -shared \
    -fPIC \    
    -o /root/initramfs/bin/module32.so \
    /root/module.c
RUN i686-linux-gnu-gcc \
    -g \
    -Wall \
    -Werror \
    -no-pie \
    -D_GNU_SOURCE \
    -lpthread \
    -o /root/initramfs/bin/target32 \
    /root/target.c    
COPY assets/cshell/test.js /root/initramfs/root/
COPY assets/initrd/init-x64 /root/initramfs/init
RUN find . | cpio -o --format=newc -R root:root > /root/initramfs-x64.img

################################################################################
# FRIDA-CSHELL                                                                 #
################################################################################
FROM platform AS frida-cshell
RUN apt-get update && \
    apt-get install -y \
    nano \
    psmisc \
    picocom \
    lrzsz \
    openssh-server \
    zssh

RUN ssh-keygen -f /root/.ssh/id_rsa -N ""
RUN cp /root/.ssh/id_rsa.pub /root/.ssh/authorized_keys
ENV FRIDA_INJECT=/usr/bin/frida-inject-64

COPY --from=kernel-arm64 /root/zImage-arm64 /root/zImage-arm64
COPY --from=kernel-arm64be /root/zImage-arm64be /root/zImage-arm64be
COPY --from=kernel-x64 /root/bzImage-x64 /root/bzImage-x64
COPY --from=initrd-arm64 /root/initramfs-arm64.img /root/initramfs-arm64.img
COPY --from=initrd-arm64be /root/initramfs-arm64be.img /root/initramfs-arm64be.img
COPY --from=initrd-x64 /root/initramfs-x64.img /root/initramfs-x64.img

RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-x86_64.xz | xz -d > /usr/bin/frida-inject-64
RUN chmod +x /usr/bin/frida-inject-64
RUN wget -qO- https://github.com/frida/frida/releases/download/17.1.4/frida-inject-17.1.4-linux-x86.xz | xz -d > /usr/bin/frida-inject-32
RUN chmod +x /usr/bin/frida-inject-32

COPY --from=initrd-x64 /root/initramfs/bin/target64 /usr/bin/target64
COPY --from=initrd-x64 /root/initramfs/bin/module64.so /usr/bin/module64.so
COPY --from=initrd-x64 /root/initramfs/bin/target32 /usr/bin/target32
COPY --from=initrd-x64 /root/initramfs/bin/module32.so /usr/bin/module32.so
COPY assets/cshell/test.js /root/
COPY assets/cshell/vm-arm64 /bin/vm-arm64
COPY assets/cshell/vm-arm64be /bin/vm-arm64be
COPY assets/cshell/vm-x64 /bin/vm-x64
COPY assets/cshell/vm-pty /bin/vm-pty

RUN mkdir /home/ws/
WORKDIR /root/npm-cache
COPY package.json /root/npm-cache
COPY package-lock.json /root/npm-cache
RUN npm install --ignore-scripts --no-audit --no-save --cache .
RUN rm -rf node_modules/
RUN rm package.json package-lock.json
WORKDIR /root