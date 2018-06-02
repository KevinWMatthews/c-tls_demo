// https://www.openssl.org/docs/man1.0.2/ssl/ssl.html
// The link for SSL's BIO (Basic IO) is broken. Use this instead:
// https://www.openssl.org/docs/man1.0.2/crypto/bio.html
// https://www.openssl.org/docs/man1.0.2/crypto/SSL_load_error_strings.html

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <strings.h>

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

    // Can also set the verify parameters for a specific SSL connection.

    /*
     * https://www.openssl.org/docs/man1.0.2/ssl/SSL_CTX_set_verify.html
     * void SSL_CTX_set_verify(SSL_CTX *ctx, int mode, int (*verify_callback)(int, X509_STORE_CTX *));
     *
     * Callback can be null.
     *
     * Valid modes for a client are:
     *      SSL_VERIFY_NONE     Continue if server does not provide cert
     *      SSL_VERIFY_PEER     Fail if server does not provide cert
     */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /*
     * void SSL_CTX_set_verify_depth(SSL_CTX *ctx,int depth);
     */
    // ?
    return ctx;
}

/*
 * Free all SSL context resources
 */
static void destroy_ssl_context(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}

/*
 * Before we perform the SSL/TLS handshake, we must connect SSL's network layer using SSL_set_fd() or SSL_set_bio().
 */
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

int ssl_connect(SSL *ssl)
{
    int ret;

    /*
     * int SSL_connect(SSL *ssl);
     *
     * SSL_connect() initiates the TLS/SSL handshake with a server.
     * The communication channel must already have been set and assigned to the ssl by setting an underlying BIO.
     *
     * Return values:
     *      1 on success
     *      0 if not successful but according to spec
     *      < 0 on error
     */
    ret = SSL_connect(ssl);
    if ( ret <= 0 )
    {
        fprintf(stderr, "%s: Failed to complete TLS handshake\n", __func__);
    }
    return ret;
}

#define CA_LIST         "../keys/ca.crt"
int load_ca_certificates(SSL_CTX *ctx)
{
    /*
     * int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
     *
     * Returns 1 on success, 0 on failure.
     */
    if ( !SSL_CTX_load_verify_locations(ctx, CA_LIST, 0) )
    {
        fprintf(stderr, "Failed to load CA cert\n");
        return -1;
    }
    return 0;
}

static int check_common_name(const char *host, X509 *cert)
{
    char peer_CN[256] = {0};

    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, peer_CN, 256);
    printf("peer_CN = %s, host = %s\n", peer_CN, host);

    if ( strcasecmp(peer_CN, host) )
    {
        fprintf(stderr, "%s: Common name doesn't match host name\n", __func__);
        return -1;
    }
    return 0;
}

/*
 * Extra checks are required for OpenSSL 1.02 or below.
 *
 * See https://wiki.openssl.org/index.php/SSL/TLS_Client#Server_Certificate
 */
int check_server_cert(SSL *ssl, const char *host)
{
    X509 *server_cert = NULL;

    // Get the server's certificate
    server_cert = SSL_get_peer_certificate(ssl);
    if (server_cert == NULL)
    {
        fprintf(stderr, "%s: Server did not provide certificate\n", __func__);
        return -1;
    }

    if ( SSL_get_verify_result(ssl) != X509_V_OK )
    {
        fprintf(stderr, "%s: Server certificate is not valid\n", __func__);
        X509_free(server_cert);
        return -1;
    }

    if ( check_common_name(host, server_cert) < 0 )
    {
        X509_free(server_cert);
        return -1;
    }

    X509_free(server_cert);
    return 0;
}

int load_ca_list(SSL_CTX *ctx, const char *ca_list)
{
    /* Load the CAs we trust*/
    if( !SSL_CTX_load_verify_locations(ctx, ca_list, 0) )
    {
        fprintf(stderr, "Can't read CA list");
        return -1;
    }
    return 0;
}

#define HOST        "localhost"
#define PORT        "8484"
int main(void)
{
    int socket_fd = SOCKETFD_INVALID;
    SSL_CTX *ctx = NULL;    // Context for SSL connection
    SSL *ssl = NULL;        // Handle for individual SSL connection

    ctx = initialize_ssl_context();
    if (ctx == NULL)
        exit(EXIT_FAILURE);

    if ( load_ca_list(ctx, CA_LIST) < 0 )
    {
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    socket_fd = tcp_connect(HOST, PORT);
    if (socket_fd < 0)
        exit(EXIT_FAILURE);

    ssl = initialize_ssl_connection(ctx, socket_fd);
    if (ssl == NULL)
    {
        close(socket_fd);
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    if ( ssl_connect(ssl) < 0 )
    {
        close(socket_fd);
        destroy_ssl_context(ctx);
        exit(EXIT_FAILURE);
    }

    check_server_cert(ssl, HOST);

    fprintf(stderr, "Shutting down client\n");
    if ( close(socket_fd) < 0 )
    {
        perror("Failed to close socket");
    }

    destroy_ssl_context(ctx);

    return 0;
}
