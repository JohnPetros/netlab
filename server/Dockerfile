FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
  apache2 \
  openssh-server \
  sudo \
  curl \
  gnupg \
  perl \
  libnet-ssleay-perl \
  openssl \
  libauthen-pam-perl \
  libpam-runtime \
  libio-pty-perl \
  libdatetime-perl \
  apt-show-versions \
  iproute2 \
  net-tools \
  nano \
  vim \
  rsyslog \
  python3 \
  && rm -rf /var/lib/apt/lists/*

# Cria usuário para teste SSH/SCP
RUN useradd -m -s /bin/bash devuser && \
  echo "devuser:devpass" | chpasswd && \
  usermod -aG sudo devuser && \
  mkdir -p /home/devuser/.ssh && \
  chown -R devuser:devuser /home/devuser/.ssh

# Configura SSH
RUN mkdir -p /var/run/sshd && \
  sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
  sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && \
  sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin no/' /etc/ssh/sshd_config && \
  echo "AllowUsers devuser" >> /etc/ssh/sshd_config

# Instala Webmin via .deb copiado localmente
COPY webmin.deb /tmp/webmin.deb
RUN apt-get update && \
  dpkg -i /tmp/webmin.deb; \
  apt-get install -f -y && \
  rm /tmp/webmin.deb && \
  rm -rf /var/lib/apt/lists/*

# Página simples do Apache
RUN echo "<h1>Apache no Container 1 (Servidor)</h1>" > /var/www/html/index.html

COPY start.sh /start.sh
RUN chmod +x /start.sh

# Scripts incorrect-password
COPY scripts/incorrect-password/ /opt/scripts/incorrect-password/
RUN chmod +x /opt/scripts/incorrect-password/*.py

# Scripts system-activity
COPY scripts/system-activity/ /opt/scripts/system-activity/
RUN chmod +x /opt/scripts/system-activity/*.py

# Scripts error-analysis
COPY scripts/error-analysis/ /opt/scripts/error-analysis/
RUN chmod +x /opt/scripts/error-analysis/*.py

EXPOSE 80 22 10000

CMD ["/start.sh"]