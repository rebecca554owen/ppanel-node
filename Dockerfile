# Build go
FROM golang:1.23.2-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN go mod download
RUN go build -v -o node -tags "sing xray hysteria2 with_reality_server with_quic with_grpc with_utls with_wireguard with_acme"

# Release
FROM  alpine
# 安装必要的工具包
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/PPanel-node/
COPY --from=builder /app/node /usr/local/bin

ENTRYPOINT [ "node", "server", "--config", "/etc/PPanel-node/config.json"]
