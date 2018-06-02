#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <openssl/ssl.h>

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

void client_handler(int socket_fd)
{
    pid_t pid;

    pid = getpid();
    printf("Entering client handler %d\n", pid);
    printf("Exiting client handler %d\n", pid);
    if ( close(socket_fd) < 0 )
    {
        perror("Client handler failed to close socket");
    }
    _exit(EXIT_SUCCESS);
}

static void handle_incoming_connections(int listen_socket)
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
        client_handler(socket_fd);
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
        handle_incoming_connections(listen_socket);
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
