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

#define CA_LIST     "keys/ca.crt"
#define CERTFILE    "keys/server.crt"
#define KEYFILE     "keys/server.pem"
#define PASSWORD    "1234"

#define PORT        8084

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
    {
        printf("%s\n", CA_LIST);
        berr_exit("Can't read CA list");
    }

    #if (OPENSSL_VERSION_NUMBER < 0x00905100L)
    SSL_CTX_set_verify_depth(ctx, 1);
    #endif

    return ctx;
}

int main(void)
{
    SSL_CTX *ctx = 0;

    print_current_ip_addr(PORT);

    OpenSSL_add_all_algorithms();

    /* Build our SSL context*/
    ctx = initialize_ctx(CERTFILE, KEYFILE, PASSWORD);

    return 0;
}
