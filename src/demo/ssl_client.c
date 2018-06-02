// https://www.openssl.org/docs/man1.0.2/ssl/ssl.html
// The link for SSL's BIO (Basic IO) is broken. Use this instead:
// https://www.openssl.org/docs/man1.0.2/crypto/bio.html

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/ssl.h>

#define SOCKETFD_INVALID        -1

/*
 * Resolve the hostname into an IP address using getaddrinfo().
 * Dynamically allocates and stores result in an addrinfo struct.
 * This addrinfo is actually a linked list of all resolutions.
 *
 * The caller is responsible for freeing this memory using freeaddrinfo()
 * Returns NULL on failure.
 */
static struct addrinfo *resolve_hostname(const char *host, const char *port)
{
    struct addrinfo hints = {0};    // Criteria
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
 * Exit on first success.
 *
 * Returns socket descriptor on success, < 0 on failure.
 */
static int connect_to_socket(struct addrinfo *addr_list)
{
    struct addrinfo *addr = NULL;
    int socket_fd = SOCKETFD_INVALID;
    int ret;

    // getaddrinfo() returns a linked list of address structures.
    // Try all of them
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
        fprintf(stderr, "Could not connect to socket\n");
        return SOCKETFD_INVALID;
    }
    return socket_fd;
}

/*
 * Connect to the host at the given port
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

SSL_CTX *initialize_ssl_context(void)
{
    const SSL_METHOD *method = NULL;
    SSL_CTX *ctx = NULL;

    SSL_library_init();

    method = SSLv23_method();
    // Can this fail?

    /*
     * SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
     *
     * Returns pointer to SSL_CTX struct on success, NULL on failure.
     */
    ctx = SSL_CTX_new(method);
    if (ctx == NULL)
    {
        fprintf(stderr, "Failed to initialize SSL context\n");
    }

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

    ctx = initialize_ssl_context();
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    tcp_connect("localhost", "8484");

    destroy_ssl_context(ctx);

    return 0;
}
