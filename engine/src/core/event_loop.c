// event_loop.c

#include "../../include/core/event_loop.h"
#include <errno.h>
#include "../../include/rules/rule_engine.h"

void safe_destroy(connection_t *conn, struct epoll_event *events, int current_idx, int nfds) 
{
    connection_destroy(conn);
    
    for (int j = current_idx + 1; j < nfds; j++) 
    {
        if (events[j].data.ptr == conn) 
        {
            events[j].data.ptr = NULL;
        }
    }
}

void start_loop_event(int listen_sock , waf_rules_t *rules , ac_node_t* root)
{
    int epfd = epoll_create1(0);

    if(epfd < 0)
    {
        perror("Error:");
        return;
    }
    
    struct epoll_event evt;
    memset(&evt , 0 , sizeof(struct epoll_event));

    evt.events = EPOLLIN;
    evt.data.ptr = connection_create(listen_sock);
    connection_t *evtConn = (connection_t *)(evt.data.ptr);
    evtConn->state = STATE_LISTENER;

    int status = epoll_ctl(epfd , EPOLL_CTL_ADD , listen_sock , &evt);

    if(status < 0)
    {
        perror("Error:");
        return;
    }
    
    int ready = -1;

    while(1)
    {
        struct epoll_event evts[100];

        if((ready = epoll_wait(epfd , evts , 100 , -1)) < 0)
            continue;

        for( int i = 0 ; i < ready ; i++)
        {
            connection_t *conn = evts[i].data.ptr;
            if(evts[i].data.ptr == NULL) continue;

            // subscribe the client to the epoll_system
            if( conn->state == STATE_LISTENER)
            {
                int new_client_sock = accept(listen_sock , NULL , NULL);

                if(new_client_sock < 0) continue;
                    
                int flags = fcntl(new_client_sock , F_GETFL);

                if(fcntl(new_client_sock , F_SETFL , flags | O_NONBLOCK) < 0)
                    return;

                struct epoll_event newEvt;
                memset(&newEvt , 0 , sizeof(struct epoll_event));
                
                newEvt.events = EPOLLIN;
                newEvt.data.ptr = connection_create(new_client_sock);

                if(epoll_ctl(epfd , EPOLL_CTL_ADD , new_client_sock , &newEvt) < 0)
                {
                    perror("Error:");
                    return;
                }
            }
            // read data from client into the conn->client_buffer
            else if(conn->state == STATE_READ_CLIENT)
            {
                printf("received Data from Client\n");

                int remaining = (sizeof(conn->client_buffer) - 1) - conn->client_buffer_len;
                if (remaining <= 0) { safe_destroy(conn , evts , i , ready); continue; }
                ssize_t len = recv(conn->client_fd, conn->client_buffer + conn->client_buffer_len, remaining, 0);
                if(len > 0 )
                {
                    conn->client_buffer_len += len;
                    
                    conn->client_buffer[conn->client_buffer_len] = '\0';
                    if(strstr(conn->client_buffer , "\r\n\r\n") == NULL)
                        continue;

                    printf("%s" , conn->client_buffer);

                    conn->state = STATE_INSPECT_REQUEST;
                    
                    struct epoll_event modEvt;
                    memset(&modEvt , 0 , sizeof(struct epoll_event));
                    modEvt.events = EPOLLOUT;
                    modEvt.data.ptr = conn;

                    if(epoll_ctl(epfd , EPOLL_CTL_MOD, conn->client_fd , &modEvt)<0)
                    {
                        perror("Error");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                }
                else if(len == 0)
                {
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }
                else if(len < 0)
                {  
                    if(errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                        perror("Error: ");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                }

            }
            //establishing the second end connection to the backend
            else if(conn->state == STATE_CONNECT_BACKEND)
            {
                int err = 0;
                socklen_t len = sizeof(err);
                if(getsockopt(conn->backend_fd , SOL_SOCKET , SO_ERROR , &err , &len) < 0 || err != 0)
                {
                    printf("Backend connection failed\n");
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }
                printf("Backend Connection established\n");
                conn->state = STATE_SEND_BACKEND;
            }
            //send data to the backend
            else if(conn->state == STATE_SEND_BACKEND)
            {
                int sent_bytes = send(conn->backend_fd , conn->client_buffer + conn->client_buffer_sent , conn->client_buffer_len  - conn->client_buffer_sent , 0);

                if(sent_bytes < 0)
                {  
                    if(errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                        perror("Error: ");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                    continue;
                }

                conn->client_buffer_sent = conn->client_buffer_sent + sent_bytes;

                if(conn->client_buffer_sent == conn->client_buffer_len)
                {
                    struct epoll_event modEvt;
                    memset(&modEvt , 0 , sizeof(struct epoll_event));
                    modEvt.events = EPOLLIN;
                    modEvt.data.ptr = conn;

                    if(epoll_ctl(epfd , EPOLL_CTL_MOD , conn->backend_fd , &modEvt) < 0)
                    {
                        perror("Error");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                    conn->state = STATE_READ_BACKEND;
                }
            }
            //reading resp from backend into conn->backend_buffer
            else if(conn->state == STATE_READ_BACKEND)
            {
                int received = recv(conn->backend_fd , conn->backend_buffer , 8191 , 0);

                if(received < 0)
                {  
                    if(errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                        perror("Error: ");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                    continue;
                }
                else if(received == 0)
                {
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }
                conn->backend_buffer_len = conn->backend_buffer_len + received;

                struct epoll_event modEvt;
                memset(&modEvt , 0 , sizeof(struct epoll_event));
                modEvt.events = EPOLLOUT;
                modEvt.data.ptr = conn;

                if(epoll_ctl(epfd , EPOLL_CTL_MOD , conn->client_fd , &modEvt) < 0)
                {
                    perror("Error");
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }
                conn->state = STATE_SEND_CLIENT;
            }
            else if(conn->state == STATE_SEND_CLIENT)
            {
                int sent_bytes = send(conn->client_fd , conn->backend_buffer + conn->backend_buffer_sent , conn->backend_buffer_len - conn->backend_buffer_sent , 0);

                if(sent_bytes < 0)
                {  
                    if(errno != EWOULDBLOCK && errno != EAGAIN)
                    {
                        perror("Error: ");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                    continue;
                }

                conn->backend_buffer_sent = conn->backend_buffer_sent + sent_bytes;

                if(conn->backend_buffer_sent == conn->backend_buffer_len)
                {
                    conn->backend_buffer_len = 0;
                    conn->backend_buffer_sent = 0;
                    conn->state = STATE_READ_BACKEND;

                    struct epoll_event modEvt ;
                    memset(&modEvt , 0 , sizeof(struct epoll_event));
                    modEvt.events = EPOLLIN;
                    modEvt.data.ptr = conn;

                    if(epoll_ctl(epfd , EPOLL_CTL_MOD , conn->client_fd , &modEvt) < 0)
                    {
                        perror("Error");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                    }
                    continue;
                }
            }
            else if (conn->state == STATE_INSPECT_REQUEST)
            {
    
                int inspector = inspect_traffic(conn , rules , root);

                if(inspector == 1)
                {
                    char *forbidden = "HTTP/1.1 403 Forbidden\r\nContent-Length: 15\r\n\r\nAccess Denied.\n";
                    send(conn->client_fd , forbidden , strlen(forbidden) , 0);
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }

                struct epoll_event muteClient;
                memset(&muteClient , 0 , sizeof(struct epoll_event));
                muteClient.events = EPOLLIN;
                muteClient.data.ptr = conn;
                if(epoll_ctl(epfd , EPOLL_CTL_MOD , conn->client_fd , &muteClient) < 0)
                {
                        perror("Error");
                        safe_destroy(conn , evts , i , ready);
                        continue;
                }

                int back_sockfd = connect_to_backend("127.0.0.1" , 8000);
                        
                if(back_sockfd < 0)
                {
                    connection_destroy(conn);
                    continue;
                }
                conn->backend_fd = back_sockfd;
                conn->state = STATE_CONNECT_BACKEND;

                struct epoll_event backEvt;
                memset(&backEvt , 0 , sizeof(struct epoll_event));
                backEvt.events = EPOLLOUT;
                backEvt.data.ptr = conn;
                if(epoll_ctl(epfd , EPOLL_CTL_ADD , back_sockfd , &backEvt) < 0)
                {
                    perror("Error");
                    safe_destroy(conn , evts , i , ready);
                    continue;
                }
            }
        }
    }
}
