#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST     "../keys/ca.crt"

#define HOST	"localhost"
#define PORT	8084

#define BUFSIZE 1500

// Global error handling struct
static BIO *bio_err = 0;


static char *host = HOST;
static int port = PORT;

/*
 * Print SSL errors and exit
 */
static int berr_exit(char *string)
{
    BIO_printf(bio_err, "%s\n", string);
    ERR_print_errors(bio_err);
    exit(0);
}

/*
 * A simple error and exit routine
 */
int err_exit(char *string)
{
    fprintf(stderr, "%s\n", string);
    exit(0);
}

/* * Create SSL context
 *
 * Initialize SSL library
 * Start error handling process
 * Load CA list
 */
SSL_CTX *initialize_ctx()
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err)
    {
        SSL_library_init();
        SSL_load_error_strings();
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);  // setup an error write context
    }

    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    if(!(SSL_CTX_load_verify_locations(ctx, CA_LIST, 0)))
        berr_exit("Can't read CA list");

    return ctx;
}

/*
 * Release all resources held by SSL context.
 */
void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}


int tcp_connect(char *host, int port)
{
    struct hostent *hp;
    struct sockaddr_in addr;
    int sock;
    int ret;

    hp = gethostbyname(host);
    if(!hp)
        err_exit("Couldn't resolve host");

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        err_exit("Could not create socket");

    ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
        err_exit("Could not connect to socket");

    return sock;

#if 0
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int sfd, s_getaddr;
    char port_string[10];

    /* Obtain address(es) matching host/port */
    sprintf(port_string, "%d", port);

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;    /* Allow IPv4 or IPv6 */
    hints.ai_socktype = SOCK_STREAM; /* Datagram socket */
    hints.ai_flags = 0;
    hints.ai_protocol = 0;          /* Any protocol AF_INET or AF_INET6*/

    s_getaddr = getaddrinfo(host, port_string, &hints, &result);
    if (s_getaddr != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(s_getaddr));
        return -1;
    }

    /* getaddrinfo() returns a list of address structures.
        Try each address until we successfully connect(2).
        If socket(2) (or connect(2)) fails, we (close the socket
        and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sfd == -1)
            continue;

        if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;                  /* Success */

        close(sfd);
    }

    if (rp == NULL) {               /* No address succeeded */
        fprintf(stderr, "Could not connect\n");
        return -1;
    }

    freeaddrinfo(result);           /* No longer needed */

    return sfd;
#endif
}

/*
 * Check that the common name matches the host name
 */
void check_cert(SSL *ssl, char *host)
{
    X509 *peer;
    char peer_CN[256] = {0};

    if ( SSL_get_verify_result(ssl) != X509_V_OK )
        berr_exit("Certificate doesn't verify");

    /* Check the cert chain.
     * The chain length is automatically checked by OpenSSL when we set the verify depth in the ctx */

    /* Check the common name */
    peer = SSL_get_peer_certificate(ssl);
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer), NID_commonName, peer_CN, 256);
    if ( strcasecmp(peer_CN, host) )
    {
        printf("peer_CN = %s, host = %s\n", peer_CN, host);
        err_exit("Common name doesn't match host name");
    }
    printf("peer_CN = %s, host = %s\n", peer_CN, host);
}

static int http_request(SSL *ssl)
{
    char xmlbuf[1024] = {0};
	char pBuf[1500] = {0};
    char buf[BUFSIZE] = {0};
    int request_len;
    int len;
    int ret;

    snprintf(xmlbuf, sizeof(xmlbuf),
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n"
        "<CubeToggleRequest>\r\n"
        "<CubeSelection>\r\n"
        "<CubeList>\r\n"
        "<MACAddress>0000005056c00008</MACAddress>\r\n"
        "</CubeList>\r\n"
        "</CubeSelection>\r\n"
        "<Action>PowerOff</Action>\r\n"
        "</CubeToggleRequest>\r\n");

    snprintf(pBuf, sizeof(pBuf)-1,
        "POST /PowerzoaServer/PowerzoaMessageServlet HTTP/1.1\r\n"
        "User-Agent: Java/1.6.0_18\r\n"
        "Host: 127.0.0.1\r\n"
        "Accept: text/html, image/gif, image/jpeg, *; q=.2, */*; q=.2\r\n"
        "Connection: keep-alive\r\n"
        "Content-Type: text/xml\r\n"
        "Content-Length: %lu\r\n\r\n",
        (long unsigned int)strlen(xmlbuf));

    request_len = strlen(pBuf);

    printf("sending %d bytes:\n"
            "---------------------\n"
            "%s\n"
            "---------------------\n",
            request_len,
            pBuf);

    ret = SSL_write(ssl, pBuf, request_len);
    switch(SSL_get_error(ssl, ret))
    {
        case SSL_ERROR_NONE:
            if(request_len != ret)
                err_exit("Incomplete write!");
            break;
        default:
            berr_exit("SSL write problem");
    }

    memset(buf, 0, BUFSIZE);

    /* Now read the server's response, assuming
       that it's terminated by a close */
    while (1)
    {
        ret = SSL_read(ssl, buf, BUFSIZE);
        switch(SSL_get_error(ssl, ret))
        {
        case SSL_ERROR_NONE:
            len = ret;
            break;
        case SSL_ERROR_ZERO_RETURN:
            goto shutdown;
        case SSL_ERROR_SYSCALL:
            fprintf(stderr, "SSL Error: Premature close\n");
            goto done;
        default:
            berr_exit("SSL read problem");
        }

        printf("Received %d bytes:\n"
        "---------------------\n"
        "%s\n"
        "\n---------------------\n",
        len,
        buf);
    }

shutdown:
    ret = SSL_shutdown(ssl);
    switch(ret)
    {
    case 1:
        break; /* Success */
    case 0:
    case -1:
    default:
        // Does this leak? Do we need to call SSL_free()?
        berr_exit("Shutdown failed");
    }

done:
    SSL_free(ssl);
    return 0;
}

int main(void)
{
    SSL_CTX *ctx = 0;
    SSL *ssl;
    BIO *sbio;
    int sock;

    OpenSSL_add_all_algorithms();
    ctx = initialize_ctx();

    sock = tcp_connect(host, port);     // Connect to the server
    if (sock < 0)
        err_exit("Failed to connect to socket");

    // Give the socket and context to the ssl engine and let it make the connection.
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    if(SSL_connect(ssl) <= 0)
        berr_exit("SSL connect error");

    // if (require_server_auth)
    check_cert(ssl, host);      // Validate the host with the CA

    http_request(ssl);

    destroy_ctx(ctx);

    return 0;
}
