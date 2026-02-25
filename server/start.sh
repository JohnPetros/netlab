#!/bin/bash
set -e

service apache2 start
service ssh start

echo "Servidor pronto:"
echo " - Apache: porta 80"
echo " - SSH: porta 22"
echo " - Usuario SSH: devuser / devpass"

# Mantém o container vivo
tail -f /dev/null