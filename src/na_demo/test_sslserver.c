#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define CA_LIST     "../keys/ca.crt"
#define CERTFILE    "../keys/server.crt"
#define KEYFILE     "../keys/server.pem"
#define PASSWORD    "1234"
#define DHFILE      "../keys/dh1024.pem"

#define PORT        8084

// http buffer
#define BUFSIZE     1500

// Global error handler
static BIO *bio_err;
static char *pass;

// Prints the IP address used for eth0
static void print_current_ip_addr(int port)
{
    struct in_addr eipaddr = {0};
    struct ifreq ifr = {0};             // See http://man7.org/linux/man-pages/man7/netdevice.7.html
    struct sockaddr_in *eth0 = {0};     // See http://man7.org/linux/man-pages/man7/ip.7.html
    int ethsock;
    char ipaddr[64] = {0};
    unsigned int i;

	// Open socket to kernel to get active ipaddr (and netmask?)
    memset(&ifr, 0, sizeof(ifr));
    eth0 = (struct sockaddr_in *)&ifr.ifr_addr;
    strcpy(ifr.ifr_name, "eth0");
    eth0->sin_family = AF_INET;
    ethsock = socket(AF_INET, SOCK_STREAM, 0);
    if (ethsock < 0)
    {
        return;     // -8;      // SOCKET_ERROR, apparently
    }

    // Get effective IP address
    i = ioctl(ethsock, SIOCGIFADDR, &ifr);
    if (i < 0)
    {
        eipaddr.s_addr = 0;     // ?
    }
    eipaddr.s_addr = eth0->sin_addr.s_addr;
    strncpy(ipaddr, (char *)inet_ntoa(eipaddr), 16);

    // Close socket
    close(ethsock);

    printf("Listening to events on server at %s:%d\n", ipaddr, port);
}

static void sigpipe_handle(int x)
{
    // Not sure if/when this happens
    printf("Received sigpipe!\n");
}

/*
 * A simple error and exit routine
 */
int err_exit(char *string)
{
    fprintf(stderr,"%s\n",string);
    exit(0);
}

/*
 * Print SSL errors and exit
 */
int berr_exit(char *string)
{
    BIO_printf(bio_err,"%s\n",string);
    ERR_print_errors(bio_err);
    exit(0);
}

/*
 * The password code is not thread safe
 */
static int password_cb(char *buf,int num, int rwflag,void *userdata)
{
    if(num<strlen(pass)+1)
        return(0);

    strcpy(buf,pass);
    return(strlen(pass));
}

/*
 * Initialize SSL context
 *
 * Start SSL Library
 * Start error handling
 * Create method (?)
 * Read certificate file
 * Read private key file
 * Load trusted CA list
 */
static SSL_CTX *initialize_ctx(char *certfile, char *keyfile, char *password)
{
    const SSL_METHOD *meth;
    SSL_CTX *ctx;

    if(!bio_err)
    {
        /* Global system initialization*/
        SSL_library_init();
        SSL_load_error_strings();

        /* An error write context */
        bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    }

    /* Set up a SIGPIPE handler */
    signal(SIGPIPE, sigpipe_handle);

    /* Create our context*/
    meth = SSLv23_method();
    ctx = SSL_CTX_new(meth);

    /* Load our keys and certificates*/
    if( !SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) )
        berr_exit("Can't read certificate file");

    pass = password;
    SSL_CTX_set_default_passwd_cb(ctx, password_cb);
    if( !SSL_CTX_use_PrivateKey_file(ctx, keyfile, SSL_FILETYPE_PEM) )
        berr_exit("Can't read key file");

    /* Load the CAs we trust*/
    if( !SSL_CTX_load_verify_locations(ctx, CA_LIST, 0) )
        berr_exit("Can't read CA list");

    #if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx, 1);
    #endif

    return ctx;
}

/*
 * Free all context resources
 */
static void destroy_ctx(SSL_CTX *ctx)
{
    SSL_CTX_free(ctx);
}


/*
 * Set Diffie-Hellman parameters in SSL Context.
 */
void load_dh_params(SSL_CTX *ctx, char *file)
{
    DH *ret = 0;
    BIO *bio = 0;

    bio = BIO_new_file(file, "r");

    if ( bio == NULL)
        berr_exit("Couldn't open DH file");

    ret = PEM_read_bio_DHparams(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if( SSL_CTX_set_tmp_dh(ctx,ret) < 0 )
        berr_exit("Couldn't set DH parameters");
}

int tcp_listen(void)
{
    int sock;
    struct sockaddr_in sin;
    int val = 1;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0)
        err_exit("Couldn't create socket");

    memset(&sin, 0, sizeof(sin));
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(PORT);
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    if( bind(sock,(struct sockaddr *)&sin, sizeof(sin)) < 0 )
        berr_exit("Couldn't bind to socket");

    listen(sock, 5);    //TODO check return value!

    return sock;
}

static int http_serve(SSL *ssl)
{
    char buf[BUFSIZE] = {0};
	char outbuf[1500] = {0};
    BIO *io, *ssl_bio;
    int n;
    int len;

    io = BIO_new(BIO_f_buffer());
    ssl_bio = BIO_new(BIO_f_ssl());
    BIO_set_ssl(ssl_bio, ssl, BIO_CLOSE);
    BIO_push(io, ssl_bio);

    len = 1;

    while (1)
    {
        while (len > 0)
        {
            memset( buf, 0, BUFSIZE );
            len = SSL_read(ssl, buf, BUFSIZE-1);

            switch(SSL_get_error(ssl, len))
            {
            case SSL_ERROR_NONE:
                break;
            case SSL_ERROR_ZERO_RETURN:
                fprintf(stderr, "SSL Read Zero bytes\n");
                break;
            case SSL_ERROR_SYSCALL:
                fprintf(stderr, "SSL Error: Premature close\n");
                return 0;
            default:
                berr_exit("SSL read problem");
            }

            printf("Received %d bytes:\n"
            "---------------------\n"
            "%s\n"
            "---------------------\n",
            len,
            buf);

            memset( outbuf, 0, sizeof(outbuf) );

            /* This is the register response from the spec */
            snprintf(outbuf, sizeof(outbuf),
            "HTTP/1.1 200 OK\r\n"
            "Server: Apache-Coyote/1.1\r\n"
            "Content-Length: 0\r\n"
            "Date: Thu, 30 Jul 2009 20:00:36 GMT\r\n\r\n");

            printf("sending %zu bytes:\n"
                "---------------------\n"
                "%s\n"
                "---------------------\n",
                strlen(outbuf),
                outbuf);

            n = SSL_write(ssl, outbuf, strlen(outbuf));
            switch(SSL_get_error(ssl, n))
            {
                case SSL_ERROR_NONE:
                    if(strlen(outbuf) != n)
                        err_exit("Incomplete write!");
                    break;
                default:
                    berr_exit("SSL write problem");
            }
        }

		// len was <= 0, which means our friend doesn't want to talk to us any more
		// Close down the connection and start over
		printf("client has closed the connection\n");
    }
    return 0;
}

void child_process(int sock, SSL_CTX *ctx)
{
    BIO *sbio = 0;
    SSL *ssl = 0;
    int r = 0;

    pid_t pid = getpid();
    printf("\nEntering child process: %d\n", pid);

    sbio = BIO_new_socket(sock, BIO_NOCLOSE);
    ssl = SSL_new(ctx);

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER|SSL_VERIFY_CLIENT_ONCE|SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    SSL_set_bio(ssl, sbio, sbio);

    r = SSL_accept(ssl);
    if (r <= 0)
        berr_exit("SSL accept error");

    printf("[%s,%s]\n", SSL_get_version(ssl), SSL_get_cipher(ssl));

    printf("Child process %d is serving http\n", pid);
    http_serve(ssl);

    printf("Exiting the child process: %d\n", pid);
    close(sock);

    // Exit without calling userspace cleanup functions (registered with atexit() [or on_exit()])
    // or flushing buffers and cleaning temp files multiple times
    _exit(0);
}

int main(void)
{
    SSL_CTX *ctx = 0;
    int sock;

    print_current_ip_addr(PORT);

    OpenSSL_add_all_algorithms();

    /* Build our SSL context*/
    ctx = initialize_ctx(CERTFILE, KEYFILE, PASSWORD);
    load_dh_params(ctx, DHFILE);

    sock = tcp_listen();

    while (1)
    {
        int s;
        pid_t pid;

        s = accept(sock, 0, 0);
        if (s < 0)
            err_exit("Error accepting socket connection");

        pid = fork();
        if (pid)
        {
            // Fork returns the PID (nonzero) in the parent process
            close(s);
        }
        else
        {
            // Fork returns 0 in the client process
            child_process(s, ctx);
        }
    }

    destroy_ctx(ctx);
    close(sock);

    return 0;
}
