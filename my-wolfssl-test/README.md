1. サーバー起動

```
gcc server.c -o server -lwolfssl -lpthread
./server
```

2. クライアント起動

```
gcc client.c -o client -lwolfssl -lpthread
./client 127.0.0.1
```

前提として wolfssl のビルド、pem ファイルの用意は完了済み
