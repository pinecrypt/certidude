ARG base_image=ubuntu:20.04
FROM $base_image as build
ENV PYTHONUNBUFFERED=1
ENV LC_ALL C.UTF-8
ENV DEBIAN_FRONTEND noninteractive

# Make apt faster
RUN echo force-unsafe-io > /etc/dpkg/dpkg.cfg.d/docker-apt-speedup
RUN echo "Dpkg::Use-Pty=0;" > /etc/apt/apt.conf.d/99quieter

RUN apt-get update -qq
RUN apt-get install -y -qq \
  python3-pip \
  openvpn \
  strongswan

# Dump on console what modules StrongSwan attempts to load
RUN echo '#!/bin/bash' > /usr/sbin/modprobe
RUN echo 'echo Attempting to load modules: $@' >> /usr/sbin/modprobe
RUN cat /usr/sbin/modprobe
RUN chmod +x /usr/sbin/modprobe

COPY entrypoint-openvpn.sh /entrypoint-openvpn.sh
COPY entrypoint-strongswan.sh /entrypoint-strongswan.sh
COPY pinecrypt/client/. /src/pinecrypt/client
COPY setup.py /src/
COPY README.md /src/
COPY misc/ /src/misc/
WORKDIR /src
RUN pip3 install .
RUN echo "#!/bin/sh" > /usr/bin/chcon
RUN chmod +x /usr/bin/chcon
