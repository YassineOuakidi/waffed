#ifndef CONNECTION_H
#define CONNECTION_H


#include <sys/epoll.h>
#include <stdlib.h>
#include <unistd.h>
#include "../rules/rule_loader.h"

enum {
    STATE_READ_CLIENT,
    STATE_CONNECT_BACKEND,
    STATE_CLOSED,
    STATE_LISTENER,
    STATE_SEND_BACKEND,
    STATE_READ_BACKEND,
    STATE_SEND_CLIENT,
    STATE_INSPECT_REQUEST
};


typedef struct connection{
    int client_fd;
    int backend_fd;
    int state;
    char client_buffer[8192];
    int client_buffer_len;
    int client_buffer_sent;
    char backend_buffer[8192];
    int backend_buffer_len;
    int backend_buffer_sent;
} connection_t;

connection_t* connection_create(int client_fd);
void connection_destroy(connection_t *conn);

#endif
