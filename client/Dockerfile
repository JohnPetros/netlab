FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  openssh-client \
  iputils-ping \
  net-tools \
  sshpass \
  curl \
  && rm -rf /var/lib/apt/lists/*

COPY test.sh /test.sh
RUN chmod +x /test.sh

CMD ["bash"]