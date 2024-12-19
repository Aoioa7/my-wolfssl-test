#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>

// wolfSSL関連
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define PORT 4443
#define BUF_SIZE 1024

typedef struct {
    WOLFSSL* ssl;
} client_info_t;

void* recv_handler(void* arg) {
    client_info_t* info = (client_info_t*)arg;
    WOLFSSL* ssl = info->ssl;
    char buf[BUF_SIZE];
    int ret;
    while (1) {
        memset(buf, 0, BUF_SIZE);
        ret = wolfSSL_read(ssl, buf, BUF_SIZE - 1);
        if (ret <= 0) {
            // サーバー切断 or エラー
            break;
        }
        printf("[RECV] %s\n", buf);
    }
    return NULL;
}


int main(int argc, char* argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_ip>\n", argv[0]);
        return 1;
    }

    const char* server_ip = argv[1];

    int sock;
    struct sockaddr_in server_addr;

    // wolfSSL初期化
    wolfSSL_Init();
    WOLFSSL_CTX* ctx = wolfSSL_CTX_new(wolfTLSv1_2_client_method());
    if (!ctx) {
        fprintf(stderr, "wolfSSL_CTX_new failed.\n");
        return 1;
    }

    // CA証明書でサーバー証明書検証
    if (wolfSSL_CTX_load_verify_locations(ctx, "ca-cert.pem", NULL) != SSL_SUCCESS) {
        fprintf(stderr, "Failed to load ca-cert.pem\n");
        return 1;
    }

    wolfSSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket");
        return 1;
    }

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family=AF_INET;
    server_addr.sin_port=htons(PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr)<=0) {
        perror("inet_pton");
        return 1;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        return 1;
    }

    WOLFSSL* ssl = wolfSSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "wolfSSL_new failed.\n");
        return 1;
    }

    wolfSSL_set_fd(ssl, sock);

    if (wolfSSL_connect(ssl) != SSL_SUCCESS) {
        fprintf(stderr, "wolfSSL_connect failed.\n");
        wolfSSL_free(ssl);
        close(sock);
        return 1;
    }

    client_info_t info;
    info.ssl = ssl;

    pthread_t tid;
    pthread_create(&tid, NULL, recv_handler, &info);
    pthread_detach(tid);

    // 標準入力からのメッセージ送信ループ
    char msg[BUF_SIZE];
    while (1) {
        if (fgets(msg, BUF_SIZE, stdin) == NULL) {
            break;
        }
        if (strcmp(msg, "/quit\n") == 0) {
            break;
        }
        int ret = wolfSSL_write(ssl, msg, strlen(msg));
        if (ret <= 0) {
            break;
        }
    }

    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    close(sock);
    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();

    return 0;
}