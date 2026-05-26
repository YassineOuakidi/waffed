//socket.c

#include "../../include/net/socket.h"
#include <unistd.h>

int create_listener_socket(int port)
{
    int sockfd = socket(AF_INET , SOCK_STREAM , 0);

    if(sockfd == -1)
    {
        perror("Error:");
        return -1;
    }
   
    int opt = 1;
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
    {
        perror("Error:");
        close(sockfd);
        return -1;
    }

    int flags = fcntl(sockfd , F_GETFL);

    if(fcntl(sockfd , F_SETFL , flags | O_NONBLOCK) < 0)
    {
        close(sockfd);
        return -1;
    }

    struct sockaddr_in socket_address;
    memset(&socket_address , 0 , sizeof(struct sockaddr_in));

    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(port); // convert to network byte order
    socket_address.sin_addr.s_addr = htonl(INADDR_ANY);

    if(bind(sockfd , (struct sockaddr *)(&socket_address) , sizeof(struct sockaddr)) < 0)
    {
        perror("Error: ");
        close(sockfd);
        return -1;
    }
    
    if(listen(sockfd , 100) < 0)
    {
        perror("Error: ");
        close(sockfd);
        return -1;
    }

    return sockfd;
}
