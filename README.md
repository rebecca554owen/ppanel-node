# PPanel-node

A PPanel node server based on multi core, modified from V2bX.  
一个基于多种内核的PPanel节点服务端，修改自V2bX，支持V2ay,Trojan,Shadowsocks,Hysteria协议。

## 软件安装

### 一键安装

```
暂无
```

## 构建
``` bash
# 通过-tags选项指定要编译的内核， 可选 xray， sing, hysteria2
go build -v -o ./node -tags "xray sing hysteria2 with_reality_server with_quic with_grpc with_utls with_wireguard with_acme" -trimpath -ldflags "-s -w -buildid="
```

