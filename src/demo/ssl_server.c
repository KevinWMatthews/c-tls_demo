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
 *
 * Call _exit() instead of exit() - this does not call teadrown functions
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

    if ( cdssl_verify_common_name(ssl, "localhost", X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS) < 0 )
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

int verify_callback(int preverify_ok, X509_STORE_CTX *x509_ctx)
{
    if (preverify_ok == 0)
    {
        fprintf(stderr, "OpenSSL rejected certificate\n");
        fprintf(stderr, "TODO print error details\n");
        return preverify_ok;
    }

    X509 * cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    if (!cert)
    {
        fprintf(stderr, "Failed to get cert\n");
        return preverify_ok;
    }

    X509_NAME *name = X509_get_subject_name(cert);
    if (!name)
    {
        fprintf(stderr, "Failed to get subject name\n");
        return preverify_ok;
    }

    fprintf(stderr, "\nReceived cert:\n");
    cdssl_print_x509_name(name);

    char peer_cn[64] = {0};
    X509_NAME_get_text_by_NID(name, NID_commonName, peer_cn, sizeof(peer_cn));

    fprintf(stderr, "Common Name: %s\n", peer_cn);

    fprintf(stderr, "Cert verification result: %d\n", preverify_ok);
    return preverify_ok;
}

#define SERVER_LISTEN_PORT      8484
#define DHFILE          "../tls_demo/keys/dh1024.pem"
// #define CA_LIST         "../tls_demo/keys/ca.crt"
#define CA_LIST           "../tls_demo/ssl2/intermediate_ca/ca-chain.crt.pem"

// #define SERVER_CERT     "../tls_demo/certs_jaimielinux/root/ca/intermediate/certs/www.example.com.cert.pem"
// #define SERVER_KEY      "../tls_demo/certs_jaimielinux/root/ca/intermediate/private/www.example.com.key.pem"
// #define SERVER_CERT     "../tls_demo/certs/intermediate/server_localhost_cert.pem"
// #define SERVER_KEY      "../tls_demo/certs/intermediate/server_localhost_key.pem"
// #define SERVER_CERT     "../tls_demo/server_chain.crt"
// #define SERVER_CERT     "../tls_demo/server_chain_short.crt"
// #define SERVER_CERT     "../tls_demo/keys/intermediate_ca.crt"
// #define SERVER_KEY      "../tls_demo/keys/intermediate_ca.key"
// #define SERVER_CERT     "../tls_demo/keys/server_intermediate_localhost.crt"
// #define SERVER_KEY      "../tls_demo/keys/server_intermediate_localhost.key"
#define SERVER_CERT     "../tls_demo/ssl/intermediate_ca/localhost_server.crt.pem"
#define SERVER_KEY      "../tls_demo/ssl/intermediate_ca/localhost_server.key.pem"
// #define SERVER_CERT     "../tls_demo/keys/server_ip.crt"
// #define SERVER_KEY      "../tls_demo/keys/server_ip.key"

int main(void)
{
    SSL_CTX *ctx = NULL;
    int listen_socket = SOCKETFD_INVALID;

    initialize_ssl_library();
    ctx = initialize_ssl_context(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, verify_callback);  // Request client certificate and fail if is not valid.
    // ctx = initialize_ssl_context(SSL_VERIFY_NONE, NULL);       // Do not request client certificate
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    long options = 0;
    options |= SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3;
    if ( cdssl_set_ssl_context_options(ctx, options) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

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

    listen_socket = tcp_listen(SERVER_LISTEN_PORT);
    if (listen_socket < 0)
    {
        fprintf(stderr, "Server failed to listen on socket. Exiting.\n");
        exit(EXIT_FAILURE);
    }

    while (1)
    {
        // Common name verification is established on a per-connection basis
        handle_incoming_connections(listen_socket, ctx);
    }

    printf("Exiting server\n");
    if ( close(listen_socket) < 0 )
    {
        perror("Server app failed to close socket on exit");
        exit(EXIT_FAILURE);
    }

    destroy_ssl_context(ctx);

    return 0;
}
