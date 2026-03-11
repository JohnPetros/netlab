for i in $(seq 1 5); do
  echo "Tentativa $i"
  nc -zv -w 3 172.28.0.10 5432 2>&1
  sleep 1
done