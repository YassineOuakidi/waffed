#ifndef BACKEND_H
#define BACKEND_H

#include <sys/socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <errno.h>


int connect_to_backend(const char *ip , int port);

#endif
