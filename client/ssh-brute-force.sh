for i in $(seq 1 6); do
  echo "Tentativa $i"
  sshpass -p 'devpass' ssh \
      -o ConnectTimeout=3 \
      -o StrictHostKeyChecking=no \
      devuser@172.28.0.10 exit 2>&1 | tail -1
  sleep 1
done