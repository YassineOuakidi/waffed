// backend.c

#include "../../include/net/backend.h"
#include <unistd.h>

int connect_to_backend(const char* ip , int port)
{

    int backend_sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if(backend_sockfd < 0)
        return -1;

    int opt = 1;
    if (setsockopt(backend_sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("Error:");
        close(backend_sockfd);
        return -1;
    }

    int flags = fcntl(backend_sockfd , F_GETFL);

    if(fcntl(backend_sockfd , F_SETFL , flags | O_NONBLOCK) < 0)
    {
        close(backend_sockfd);
        return -1;
    }
    struct sockaddr_in socket_address;
    memset(&socket_address , 0 , sizeof(struct sockaddr_in));

    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port); // convert to network byte order

    if(inet_pton(AF_INET, ip, &socket_address.sin_addr) <= 0)
    {
        printf("[-] Invalid backend IP address: %s\n", ip);
        close(backend_sockfd);
        return -1;
    }

    if(connect(backend_sockfd , (struct sockaddr *)(&socket_address) , sizeof(struct sockaddr)) < 0)
    {
        if(errno == EINPROGRESS)
        {
            return backend_sockfd;
        }
        close(backend_sockfd);
        return -1;
    }

    return backend_sockfd;
}
