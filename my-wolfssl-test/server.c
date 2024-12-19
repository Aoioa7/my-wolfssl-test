#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <errno.h>

// wolfSSL関連
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>
#include <wolfssl/wolfcrypt/error-crypt.h>

#define PORT 4443
#define MAX_CLIENTS 10
#define BUF_SIZE 1024

typedef struct {
    WOLFSSL* ssl;
    int active;
} client_t;

static WOLFSSL_CTX* ctx = NULL;
static client_t clients[MAX_CLIENTS];
static pthread_mutex_t clients_lock = PTHREAD_MUTEX_INITIALIZER;

void broadcast_message(const char* msg, int exclude_index) {
    pthread_mutex_lock(&clients_lock);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (i != exclude_index && clients[i].active) {
            int ret = wolfSSL_write(clients[i].ssl, msg, strlen(msg));
            if (ret <= 0) {
                // 書き込みエラー
				fprintf(stderr, "%d: wolfSSL_write failed.\n",i);
            }
        }
    }
    pthread_mutex_unlock(&clients_lock);
}

void* client_handler(void* arg) {
    int index = *(int*)arg;
    free(arg);

    char buf[BUF_SIZE];
    int ret;
    WOLFSSL* ssl = clients[index].ssl;

    // クライアントハンドリングループ
    while (1) {
        memset(buf, 0, BUF_SIZE);
        ret = wolfSSL_read(ssl, buf, BUF_SIZE - 1);
        if (ret <= 0) {
            // 通信切断またはエラー
            break;
        }

        // 受信したメッセージを他クライアントへブロードキャスト
        broadcast_message(buf, index);
    }

    // 終了処理
    pthread_mutex_lock(&clients_lock);
    wolfSSL_shutdown(ssl);
    wolfSSL_free(ssl);
    clients[index].active = 0;
    pthread_mutex_unlock(&clients_lock);

    return NULL;
}

int create_socket(int* server_fd,struct sockaddr_in* server_addr,int opt) {
	    int fd;
	  if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
        perror("socket failed");
        return 1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(server_addr, 0, sizeof(*server_addr));
    server_addr->sin_family = AF_INET;
    server_addr->sin_addr.s_addr = INADDR_ANY;
    server_addr->sin_port = htons(PORT);

    if (bind(fd, (struct sockaddr*)server_addr, sizeof(*server_addr))<0) {
        perror("bind failed");
		close(fd);
        return 1;
    }

    if (listen(fd, 5) < 0) {
        perror("listen failed");
		close(fd);
        return 1;
    }
	*server_fd = fd;
	return 0;
}


int main() {
    int server_fd;
    struct sockaddr_in server_addr;
    int opt = 1;

    // wolfSSLライブラリ初期化
    wolfSSL_Init();
    ctx = wolfSSL_CTX_new(wolfTLSv1_2_server_method());
    if (ctx == NULL) {
        fprintf(stderr, "wolfSSL_CTX_new failed.\n");
        return 1;
    }

    // サーバー証明書、秘密鍵読み込み
    if (wolfSSL_CTX_use_certificate_file(ctx, "server-cert.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server certificate.\n");
        return 1;
    }
    if (wolfSSL_CTX_use_PrivateKey_file(ctx, "server-key.pem", SSL_FILETYPE_PEM) != SSL_SUCCESS) {
        fprintf(stderr, "Error loading server key.\n");
        return 1;
    }

    // ソケット作成
    if (create_socket(&server_fd,&server_addr,opt) == 1) {
		return 1;
	}

    printf("Server listening on port %d...\n", PORT);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_sock = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
        if (client_sock < 0) {
            perror("accept");
            continue;
        }

        // wolfSSL用SSLオブジェクト生成
        WOLFSSL* ssl = wolfSSL_new(ctx);
        if (!ssl) {
            fprintf(stderr, "wolfSSL_new failed.\n");
            close(client_sock);
            continue;
        }

        wolfSSL_set_fd(ssl, client_sock);

        if (wolfSSL_accept(ssl) != SSL_SUCCESS) {
            fprintf(stderr, "wolfSSL_accept failed.\n");
            wolfSSL_free(ssl);
            close(client_sock);
            continue;
        }

        // クライアントスロットを確保
        pthread_mutex_lock(&clients_lock);
        int idx = -1;
        for (int i = 0; i < MAX_CLIENTS; i++) {
            if (!clients[i].active) {
                clients[i].ssl = ssl;
                clients[i].active = 1;
                idx = i;
                break;
            }
        }
        pthread_mutex_unlock(&clients_lock);

        if (idx == -1) {
            // 定員オーバー
            wolfSSL_shutdown(ssl);
            wolfSSL_free(ssl);
            close(client_sock);
            continue;
        }

        int* arg = malloc(sizeof(int));
        *arg = idx;
        pthread_t tid;
        pthread_create(&tid, NULL, client_handler, arg);
        pthread_detach(tid);

    }

    wolfSSL_CTX_free(ctx);
    wolfSSL_Cleanup();
    return 0;
}