#include "cdssl.h"
#include <openssl/ssl.h>
#include <openssl/err.h>


// Handle to SSL Basic IO context for printing errors.
static BIO *bio_err;

/*
 * Print custom user message to OpenSSL's error IO.
 *
 * Use for printing errors that occur in user code.
 */
//TODO add varargs?
void print_error(char *string)
{
    // Print user's string to BIO file handle
    BIO_printf(bio_err, "%s", string);
}

/*
 * Print custom user message and OpenSSL's error message to SSL Basic IO handle.
 *
 * Use for printing details of errors that stem from the SSL library.
 */
int ssl_print_error(char *string)
{
    print_error(string);
    ERR_print_errors(bio_err);              // Print information on SSL library error
}


void initialize_ssl_library(void)
{
    // add_all_algorithms?
    SSL_library_init();

    // Add SSL Basic IO construct for error handling.
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);      // I don't know if/how to free this.
}
