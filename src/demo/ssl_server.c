#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cdssl.h"

#define SOCKETFD_INVALID        -1

int ssl_accept(SSL *ssl)
{
    int ret;

    /*
     * int SSL_accept(SSL *ssl);
     *
     * SSL_accept() waits for a TLS/SSL client to initiate the TLS/SSL handshake.
     * The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
     *
     * Return values:
     *      1 on success
     *      0 if not successful but according to spec
     *      < 0 on error
     */
    ret = SSL_accept(ssl);
    if ( ret <= 0 )
    {
        fprintf(stderr, "%s: Failed to complete TLS handshake\n", __func__);
    }
    return ret;
}

/*
 * Set Diffie-Hellman parameters in SSL Context.
 */
int load_dh_params(SSL_CTX *ctx, char *file)
{
    DH *ret = 0;
    BIO *bio = 0;

    bio = BIO_new_file(file, "r");

    if ( bio == NULL)
    {
        fprintf(stderr, "%s: Couldn't open DH file", __func__);
        return -1;
    }

    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if( SSL_CTX_set_tmp_dh(ctx,ret) < 0 )       // What does this do?
    {
        fprintf(stderr, "%s: Couldn't set DH parameters", __func__);
        return -1;
    }

    return 0;
}

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

#define DHFILE      "../keys/dh1024.pem"
#define CA_LIST         "../keys/ca.crt"
#define SERVER_CERT     "../keys/server.crt"
#define SERVER_KEY      "../keys/server.pem"
int main(void)
{
    SSL_CTX *ctx = NULL;
    int listen_socket = SOCKETFD_INVALID;

    initialize_ssl_library();

    ctx = initialize_ssl_context(SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT);
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    if ( load_dh_params(ctx, DHFILE) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    if ( load_ca_list(ctx, CA_LIST) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    if ( load_certificate_and_key(ctx, SERVER_CERT, SERVER_KEY) < 0 )
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
