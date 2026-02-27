#!/bin/bash
# 1. Kill old processes
pkill -9 -f clouddns-bin || true
docker rm -f clouddns-prom-fresh || true

# 2. Build fresh
go build -o clouddns-bin cmd/clouddns/main.go

# 3. Start cloudDNS (Binding to all interfaces)
export DATABASE_URL="postgres://postgres:postgres@localhost:5432/clouddns?sslmode=disable"
export API_ADDR="0.0.0.0:8080"
nohup ./clouddns-bin > server.log 2>&1 &
CLOUDDNS_PID=$!
echo "cloudDNS started with PID: $CLOUDDNS_PID"

# 4. Wait for server to be ready
echo "Waiting for server to start..."
for i in {1..10}; do
    if curl -s http://localhost:8080/health > /dev/null; then
        echo "Server is UP"
        break
    fi
    sleep 1
done

# 5. Start Prometheus
docker run -d --name clouddns-prom-fresh -p 9091:9090 -v $(pwd)/prometheus.yml:/etc/prometheus/prometheus.yml prom/prometheus

# 6. Generate traffic in background
echo "Starting traffic..."
nohup go run cmd/bench/main.go -server 127.0.0.1:10053 -n 1000000 -c 10 > bench.log 2>&1 &

echo "Demo fully started."
echo "Check metrics at: http://localhost:9091"
