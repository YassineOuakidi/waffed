//connection.c

#include "../../include/core/connection.h"

connection_t* connection_create(int client_fd)
{
    connection_t* conn = calloc(1 , sizeof(connection_t));
    if(conn == NULL)
        return NULL;

    conn->client_fd = client_fd;
    conn->backend_fd = -1;
    conn->state = STATE_READ_CLIENT;
    conn->client_buffer_sent = 0;
    conn->backend_buffer_sent = 0;
    return conn;
}

void connection_destroy(connection_t* conn)
{
    close(conn->client_fd);
    if(conn->backend_fd != -1) close(conn->backend_fd);
    free(conn);
}
