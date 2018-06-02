#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#define SOCKETFD_INVALID        -1

static int tcp_listen(unsigned int port)
{
    int socket_fd = SOCKETFD_INVALID;
    struct sockaddr_in sin = {0};
    int val = 1;
    int ret;

    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (socket_fd < 0)
    {
        perror("Failed to create socket");
        return SOCKETFD_INVALID;
    }

    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(port);
    ret = setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));
    if (ret < 0)
    {
        perror("Failed to set socket option");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    ret = bind(socket_fd, (struct sockaddr *)&sin, sizeof(sin));
    if (ret < 0)
    {
        perror("Failed to bind to socket");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    ret = listen(socket_fd, 5);
    if (ret < 0)
    {
        perror("Failed to listen on socket");
        close(socket_fd);
        return SOCKETFD_INVALID;
    }

    return socket_fd;
}

void client_handler(int socket_fd)
{
    pid_t pid;

    pid = getpid();
    printf("Entering client handler %d\n", pid);
    printf("Exiting client handler %d\n", pid);
    if ( close(socket_fd) < 0 )
    {
        perror("Client handler failed to close socket");
    }
    _exit(EXIT_SUCCESS);
}

int main(void)
{
    int listen_socket = SOCKETFD_INVALID;

    listen_socket = tcp_listen(8484);
    if (listen_socket < 0)
    {
        fprintf(stderr, "Server failed to listen on socket. Exiting.\n");
        return -1;
    }

    while (1)
    {
        int socket_fd = SOCKETFD_INVALID;
        pid_t pid;

        printf("\nWaiting for a socket connection...\n");
        socket_fd = accept(listen_socket, 0, 0);
        if (socket_fd < 0)
        {
            perror("Failed to accept connection");
            continue;       // Hope for the best?
        }

        pid = fork();
        if (pid < 0)
        {
            perror("Failed to fork client handler");
            close(socket_fd);
            close(listen_socket);
            exit(EXIT_FAILURE);
        }
        else if (pid == 0)
        {
            // Child process
            client_handler(socket_fd);
        }
        else
        {
            // Parent process
            printf("Spawning client handler %d\n", pid);
            if ( close(socket_fd) < 0 )     // Close the socket in the parent process. It should still be open in the child process?
            {
                perror("Server app failed to close socket");
            }
        }
    }

    printf("Exiting server app\n");
    if ( close(listen_socket) < 0 )
    {
        perror("Server app failed to close socket on exit");
        return -1;
    }

    return 0;
}
