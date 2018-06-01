#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <string.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST     "keys/ca.crt"

#define HOST	"localhost"
#define PORT	8084

// Global error handling struct
static BIO *bio_err = 0;


static char *host = HOST;
static int port = PORT;

/*
 * Print SSL errors and exit
 */
static int berr_exit(char *string)
{
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
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
        berr_exit("Couldn't resolve host");

    memset(&addr, 0, sizeof(addr));
    addr.sin_addr = *(struct in_addr*)hp->h_addr_list[0];
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    sock = socket(AF_INET,SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0)
        berr_exit("Could not create socket");

    ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0)
        berr_exit("Could not connect to socket");

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
        berr_exit("Failed to connect to socket");

    // Give the socket and context to the ssl engine and let it make the connection.
    ssl = SSL_new(ctx);
    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    SSL_set_bio(ssl, sbio, sbio);

    if(SSL_connect(ssl) <= 0)
        berr_exit("SSL connect error");

    destroy_ctx(ctx);

    return 0;
}
