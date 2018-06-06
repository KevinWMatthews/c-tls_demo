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
#include <openssl/err.h>
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

static int check_common_name(X509 *cert, const char *host)
{
    char peer_CN[256] = {0};

    X509_NAME_get_text_by_NID(X509_get_subject_name(cert), NID_commonName, peer_CN, 256);
    printf("peer_CN = %s, host = %s\n", peer_CN, host);

    if ( strcasecmp(peer_CN, host) )
    {
        print_error("Common name doesn't match host name\n");
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
        print_error("Server did not provide certificate\n");
        return -1;
    }

    // Verify that the handshake was successful
    if ( SSL_get_verify_result(ssl) != X509_V_OK )
    {
        print_error("Server certificate is not valid\n");
        X509_free(server_cert);
        return -1;
    }

    // Verify that the common name matches the host name
    if ( check_common_name(server_cert, host) < 0 )
    {
        X509_free(server_cert);
        return -1;
    }

    X509_free(server_cert);
    return 0;
}

/*
 * Load certificate chain file and corresponding private key file, then check the private key.
 * Returns 0 on success, -1 on failure.
 */
static int load_certificate_and_key(SSL_CTX *ctx, const char *cert_file, const char *key_file)
{
    /*
     * int SSL_CTX_use_certificate_chain_file(SSL_CTX *ctx, const char *file);
     *
     * SSL_CTX_use_certificate_chain_file() loads a certificate chain from file into ctx.
     * The certificates must be in PEM format and must be sorted starting with the subject's certificate
     * (actual client or server certificate), followed by intermediate CA certificates if applicable,
     * and ending at the highest level (root) CA
     *
     * Returns 1 on success, not 1 on error.
     */
    if ( SSL_CTX_use_certificate_chain_file(ctx, cert_file) != 1 )
    // if ( SSL_CTX_use_certificate_file(ctx, CLIENT_CERT, SSL_FILETYPE_PEM) != 1 )
    {
        ssl_print_error("Error loading certificate chain\n");
        return -1;
    }


    //TODO Should enter passphrase for key?
    // SSL_CTX_set_default_passwd_cb()
    // or
    // SSL_CTX_set_default_passwd_cb()
    /*
     * int SSL_CTX_use_PrivateKey_file(SSL_CTX *ctx, const char *file, int type);
     *
     * Returns 1 on success, not 1 on error.
     */
    if ( SSL_CTX_use_PrivateKey_file(ctx, key_file, SSL_FILETYPE_PEM) != 1 )
    {
        ssl_print_error("Error loading private key\n");
        return -1;
    }

    /*
     * int SSL_CTX_check_private_key(const SSL_CTX *ctx);
     */
    if ( SSL_CTX_check_private_key(ctx) != 1 )
    {
        ssl_print_error("Failed to check private key\n");
        return -1;
    }

    return 0;
}

int load_ca_list(SSL_CTX *ctx, const char *ca_list)
{
    /*
     * int SSL_CTX_load_verify_locations(SSL_CTX *ctx, const char *CAfile, const char *CApath);
     *
     * Returns 1 on success, 0 on failure.
     */
    if( !SSL_CTX_load_verify_locations(ctx, ca_list, 0) )
    {
        ssl_print_error("Can't read CA list");
        return -1;
    }
    return 0;
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

    ctx = initialize_ssl_context();
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
