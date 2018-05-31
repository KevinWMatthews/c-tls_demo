#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <openssl/ssl.h>

#define PORT        8084

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

int main(void)
{
    print_current_ip_addr(PORT);

    OpenSSL_add_all_algorithms();

    return 0;
}
