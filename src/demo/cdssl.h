#ifndef CDSSL_INCLUDED
#define CDSSL_INCLUDED

/*
 * Initialize the SSL library and set up the IO handle for printing errors.
 *
 * Do not call this function twice!
 */
void initialize_ssl_library(void);

// Pull these private again?
void print_error(char *string);
int ssl_print_error(char *string);

#endif
