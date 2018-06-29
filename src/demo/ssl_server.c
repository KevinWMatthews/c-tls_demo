#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cdssl.h"

#define SOCKETFD_INVALID        -1

static int tcp_listen(unsigned int port)
{
    int socket_fd = SOCKETFD_INVALID;
    struct sockaddr_in sin = {0};
    int val = 1;
    int ret;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Failed to create socket");
        return SOCKETFD_INVALID;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if (ret < 0)
    {
        perror("Failed to set socket option");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    ret = bind(socket_fd, (struct sockaddr *)&sin, sizeof(sin));
    if (ret < 0)
    {
        perror("Failed to bind to socket");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    ret = listen(socket_fd, 5);
    if (ret < 0)
    {
        perror("Failed to listen on socket");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    return socket_fd;
}

/*
 * Create an SSL connection.
 *
 * Do not close the SSL context - this belongs to the parent process and is reused for each child.
 */
void client_handler(int socket_fd, SSL_CTX *ctx)
{
    pid_t pid;
    SSL *ssl = NULL;

    pid = getpid();
    printf("Entering client handler %d\n", pid);

    ssl = initialize_ssl_connection(ctx, socket_fd);
    if (ssl == NULL)
    {
        close(socket_fd);
        _exit(EXIT_FAILURE);
    }

    ssl_accept(ssl);

    printf("Exiting client handler %d\n", pid);
    if ( close(socket_fd) < 0 )
    {
        perror("Client handler failed to close socket");
    }
    _exit(EXIT_SUCCESS);
}

static void handle_incoming_connections(int listen_socket, SSL_CTX *ctx)
{
    int socket_fd = SOCKETFD_INVALID;
    pid_t pid;

    printf("\nWaiting for a socket connection...\n");
    socket_fd = accept(listen_socket, 0, 0);
    if (socket_fd < 0)
    {
        perror("Failed to accept connection");
        return;         // Hope for the best?
    }

    pid = fork();
    if (pid < 0)
    {
        perror("Failed to fork client handler");
        close(socket_fd);
        close(listen_socket);
        exit(EXIT_FAILURE);
    }
    else if (pid == 0)
    {
        // Child process
        client_handler(socket_fd, ctx);
        fprintf(stderr, "Child process leaked!\n");
    }
    else
    {
        // Parent process
        printf("Server spawning client handler %d\n", pid);
        if ( close(socket_fd) < 0 )     // Close the socket in the parent process. It should still be open in the child process?
        {
            perror("Server failed to close socket");
        }
    }
}

#include <openssl/x509.h>
// This hits twice? I wonder why.
int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    if (preverify_ok == 0)
    {
        fprintf(stderr, "cert verification error\n");
        return preverify_ok;
    }

    X509 * cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (!cert)
    {
        fprintf(stderr, "failed to get cert\n");
        return preverify_ok;
    }

    X509_NAME *name = X509_get_subject_name(cert);
    if (!name)
    {
        fprintf(stderr, "failed to get subject name\n");
        return preverify_ok;
    }

    fprintf(stderr, "\nReceived cert:\n");
    cdssl_print_x509_name(name);

    char peer_cn[64] = {0};
    X509_NAME_get_text_by_NID(name, NID_commonName, peer_cn, sizeof(peer_cn));

    fprintf(stderr, "Common Name: %s\n", peer_cn);

#if 0
#define MY_COMMON_NAME "common_name"
    unsigned int flags = 0;     //TODO What are these?
    char actual_peer_cn[64] = {0};
    int ret;

    ret = X509_check_host(cert, MY_COMMON_NAME, sizeof(MY_COMMON_NAME), flags, &actual_peer_cn);
    fprintf(stderr, "ret: %d\n", ret);
#endif

    fprintf(stderr, "preverify_ok: %d\n", preverify_ok);
    return preverify_ok;
}

#define DHFILE          "../keys2/dh1024.pem"
#define CA_LIST         "../keys2/ca2.crt"
#define SERVER_CERT     "../keys2/server2.crt"
#define SERVER_KEY      "../keys2/server2.key"
int main(void)
{
    SSL_CTX *ctx = NULL;
    int listen_socket = SOCKETFD_INVALID;

    fprintf(stderr, "%s\n", OpenSSL_version(OPENSSL_VERSION));      //TODO Extract this
    initialize_ssl_library();
    ctx = initialize_ssl_context2(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);  // Request client certificate and fail if is not valid.
    // ctx = initialize_ssl_context2(SSL_VERIFY_NONE, NULL);       // Do not request client certificate
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    if ( load_dh_params(ctx, DHFILE) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    // Load certificate and key for when client does server-side authentication.
    if ( load_certificate_and_key(ctx, SERVER_CERT, SERVER_KEY) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    // Load CA list for doing client-side authentication
    if ( load_ca_list(ctx, CA_LIST) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    listen_socket = tcp_listen(8484);
    if (listen_socket < 0)
    {
        fprintf(stderr, "Server failed to listen on socket. Exiting.\n");
        return -1;
    }

    while (1)
    {
        handle_incoming_connections(listen_socket, ctx);
    }

    printf("Exiting server\n");
    if ( close(listen_socket) < 0 )
    {
        perror("Server app failed to close socket on exit");
        return -1;
    }

    destroy_ssl_context(ctx);

    return 0;
}
