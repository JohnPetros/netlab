#!/bin/bash
set -e

echo "== Teste 1: conectividade de rede =="
ping -c 2 server

echo
echo "== Teste 2: SSH no servidor =="
sshpass -p 'devpass' ssh -o StrictHostKeyChecking=no devuser@server 'echo "SSH OK em $(hostname)"'

echo
echo "== Teste 3: criar arquivo local e transferir via SCP =="
echo "Arquivo criado no client em $(date)" > /tmp/arquivo_poc.txt

sshpass -p 'devpass' scp -o StrictHostKeyChecking=no /tmp/arquivo_poc.txt devuser@server:/home/devuser/

echo
echo "== Teste 4: validar arquivo no servidor =="
sshpass -p 'devpass' ssh -o StrictHostKeyChecking=no devuser@server 'ls -l /home/devuser/arquivo_poc.txt && cat /home/devuser/arquivo_poc.txt'

echo
echo "== Teste 5: Apache acessível =="
curl -s http://server | head -n 1

echo
echo "POC concluída com sucesso ✅"