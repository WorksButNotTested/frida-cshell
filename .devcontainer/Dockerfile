FROM ubuntu:22.04 as frida-cshell
RUN apt-get update && \
  apt-get install -y \
  build-essential \
  curl \
  git \
  lib32stdc++-9-dev \
  libc6-dev-i386 \
  python3-dev \
  python3-pip \
  psmisc
RUN curl -fsSL https://deb.nodesource.com/setup_20.x -o /tmp/node.sh
RUN bash /tmp/node.sh
RUN apt-get install -y nodejs
RUN curl -fsSL https://github.com/frida/frida/releases/download/16.2.1/frida-inject-16.2.1-linux-x86_64.xz -o /tmp/frida-inject-16.2.1-linux-x86_64.xz
RUN unxz /tmp/frida-inject-16.2.1-linux-x86_64.xz
RUN mv /tmp/frida-inject-16.2.1-linux-x86_64 /usr/local/bin/frida-inject
RUN chmod +x /usr/local/bin/frida-inject
