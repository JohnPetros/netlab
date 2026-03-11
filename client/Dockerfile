FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  openssh-client \
  iputils-ping \
  net-tools \
  netcat \
  sshpass \
  curl \
  && rm -rf /var/lib/apt/lists/*

COPY test.sh /test.sh
COPY ssh-brute-force.sh /ssh-brute-force.sh
COPY test-db-connection.sh /test-db-connection.sh
RUN chmod +x /test.sh /ssh-brute-force.sh /test-db-connection.sh

CMD ["bash"]