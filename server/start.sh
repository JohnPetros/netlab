#!/bin/bash
set -e

service apache2 start
service ssh start
/etc/webmin/start
rsyslogd

echo "Servidor pronto:"
echo " - Apache:  porta 80"
echo " - SSH:     porta 22"
echo " - Webmin:  porta 10000  (https://localhost:10000)"
echo " - Usuario SSH/Webmin: devuser / devpass"

# Mantém o container vivo
tail -f /dev/null