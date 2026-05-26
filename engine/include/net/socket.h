#ifndef SOCKET_H
#define SOCKET_H

#include <sys/socket.h>
#include <fcntl.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <string.h>


int create_listener_socket(int port);


#endif
