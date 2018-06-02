#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>

#define SOCKETFD_INVALID        -1

// Extract this?
static SSL *initialize_ssl_connection(SSL_CTX *ctx, int socket_fd)
{
    SSL *ssl = NULL;
    BIO *socket_bio = NULL;     // Basic IO for socket

    /*
     * SSL *SSL_new(SSL_CTX *ctx);
     *
     * Returns a pointer on success and NULL on failure.
     */
    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        fprintf(stderr, "Error creating SSL context\n");
        return NULL;
    }

    /*
     * BIO *BIO_new_socket(int sock, int close_flag);
     *
     * If set, close_flag will automatically close the socket when the bio is freed. Could be nice?
     * The BIO is automatically freed when the corresponding SSL object is free. You'd better associate it with an SSL object?
     * Returns a pointer on success and NULL on failure.
     */
    socket_bio = BIO_new_socket(socket_fd, BIO_NOCLOSE);
    if (socket_bio == NULL)
    {
        fprintf(stderr, "Failed to create BIO for SSL socket\n");
        SSL_free(ssl);
        return NULL;
    }

    /*
     * void SSL_set_bio(SSL *ssl, BIO *rbio, BIO *wbio);
     *
     * Set read and write Basic IO's for the SSL connection.
     * Can not fail.
     */
    SSL_set_bio(ssl, socket_bio, socket_bio);

    return ssl;
}

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

/*
 * Initialize SSL library
 * Set TLS method
 * Load certificates
 *
 * Returns SSL context on success, NULL on failure.
 * The caller is responsible for freeing the SSL context using SSL_CTX_free().
 */
SSL_CTX *initialize_ssl_context(void)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx;

    SSL_library_init();
    // SSL_Load_error_string();

    method = SSLv23_method();       // Can limit to server_method() or _client_method()
    // Can this fail?

    // Can limit available methos using SSL_CTX_set_options()
    ctx = SSL_CTX_new(method);
    if (!ctx)
    {
        fprintf(stderr, "Failed to initialize SSL context\n");
    }

    // ? #if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;
}

/*
 * Free all SSL context resources
 */
static void destroy_ssl_context(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

int main(void)
{
    SSL_CTX *ctx = NULL;
    int listen_socket = SOCKETFD_INVALID;

    ctx = initialize_ssl_context();
    if (ctx == NULL)
        exit(EXIT_FAILURE);

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
