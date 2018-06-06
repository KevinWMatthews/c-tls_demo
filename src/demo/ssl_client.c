// https://www.openssl.org/docs/man1.0.2/ssl/ssl.html
// The link for SSL's BIO (Basic IO) is broken. Use this instead:
// https://www.openssl.org/docs/man1.0.2/crypto/bio.html
// https://www.openssl.org/docs/man1.0.2/crypto/SSL_load_error_strings.html

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "cdssl.h"

#define SOCKETFD_INVALID        -1


/*
 * Resolve the hostname into an IP address using getaddrinfo().
 *
 * Dynamically allocates and stores result in an addrinfo struct.
 * This addrinfo is actually a linked list of all resolutions.
 *
 * The caller is responsible for freeing this memory using freeaddrinfo()
 * Returns NULL on failure.
 */
static struct addrinfo *resolve_hostname(const char *host, const char *port)
{
    struct addrinfo hints = {0};        // Criteria
    struct addrinfo *result = NULL;
    int ret;

    hints.ai_family = AF_UNSPEC;        // IPv4 or IPv6 (or Unix?)
    hints.ai_socktype = SOCK_STREAM;    // TCP socket
    hints.ai_protocol = 0;              // Any protocol?
    hints.ai_flags = 0;

    // See https://linux.die.net/man/3/getaddrinfo
    // int getaddrinfo(const char *node, const char *service,
    //              const struct addrinfo *hints,
    //              struct addrinfo **res)
    ret = getaddrinfo(host, port, &hints, &result);
    if (ret != 0)
    {
        fprintf( stderr, "Error resolving hostname: %s\n", gai_strerror(ret) );
        return NULL;
    }

    return result;
}

/*
 * Try to connect to each of the addresses in the linked list.
 *
 * Exits on first success.
 * Returns socket descriptor on success, < 0 on failure.
 */
static int connect_to_socket(struct addrinfo *addr_list)
{
    struct addrinfo *addr = NULL;
    int socket_fd = SOCKETFD_INVALID;
    int ret;

    // getaddrinfo() returns a linked list of address structures.
    // Try each of them until one works.
    for (addr = addr_list; addr != NULL; addr = addr->ai_next)
    {
        socket_fd = socket(addr->ai_family, addr->ai_socktype, addr->ai_protocol);
        if (socket_fd < 0)
        {
            perror("Could not open socket");
            continue;
        }

        ret = connect(socket_fd, addr->ai_addr, addr->ai_addrlen);
        if (ret == 0)
            break;      // success
    }

    if (addr == NULL)
    {
        print_error("Could not connect to socket\n");
        return SOCKETFD_INVALID;
    }
    return socket_fd;
}

/*
 * Connect to the host at the given port.
 *
 * Returns socket descriptor on success, < 0 on failure.
 */
int tcp_connect(const char *host, const char *port)
{
    struct addrinfo *addr_list = NULL;
    int socket_fd = SOCKETFD_INVALID;
    int ret;

    addr_list = resolve_hostname(host, port);
    if (!addr_list)
        return SOCKETFD_INVALID;

    socket_fd = connect_to_socket(addr_list);

    freeaddrinfo(addr_list);

    return socket_fd;
}


#define HOST        "localhost"
#define PORT        "8484"
#define CA_LIST         "../keys/ca.crt"
#define CLIENT_CERT     "../keys/client.crt"
#define CLIENT_KEY      "../keys/client.pem"
int main(void)
{
    int socket_fd = SOCKETFD_INVALID;
    SSL_CTX *ctx = NULL;    // Context for SSL connection
    SSL *ssl = NULL;        // Handle for individual SSL connection

    initialize_ssl_library();

    ctx = initialize_ssl_context(SSL_VERIFY_PEER);
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    if ( load_ca_list(ctx, CA_LIST) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    if ( load_certificate_and_key(ctx, CLIENT_CERT, CLIENT_KEY) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    socket_fd = tcp_connect(HOST, PORT);
    if (socket_fd < 0)
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    ssl = initialize_ssl_connection(ctx, socket_fd);
    if (ssl == NULL)
    {
        destroy_ssl_context(ctx);
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    if ( ssl_connect(ssl) < 0 )
    {
        destroy_ssl_connection(ssl);
        destroy_ssl_context(ctx);
        close(socket_fd);
        exit(EXIT_FAILURE);
    }

    check_server_cert(ssl, HOST);

    fprintf(stderr, "Shutting down client\n");
    destroy_ssl_connection(ssl);
    destroy_ssl_context(ctx);
    if ( close(socket_fd) < 0 )
    {
        perror("Failed to close socket");
    }

    return 0;
}
