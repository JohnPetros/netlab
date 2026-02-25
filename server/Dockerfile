FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  apache2 \
  openssh-server \
  sudo \
  && rm -rf /var/lib/apt/lists/*

# Cria usuário para teste SSH/SCP
RUN useradd -m -s /bin/bash devuser && \
  echo "devuser:devpass" | chpasswd && \
  mkdir -p /home/devuser/.ssh && \
  chown -R devuser:devuser /home/devuser/.ssh

# Configura SSH
RUN mkdir -p /var/run/sshd && \
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
  sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
  echo "AllowUsers devuser" >> /etc/ssh/sshd_config

# Página simples do Apache
RUN echo "<h1>Apache no Container 1 (Servidor)</h1>" > /var/www/html/index.html

COPY start.sh /start.sh
RUN chmod +x /start.sh

EXPOSE 80 22

CMD ["/start.sh"]