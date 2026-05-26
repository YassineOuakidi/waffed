//rule_engine.c

#include "../../include/rules/rule_engine.h"

int check_conn(http_request_t* req , ac_node_t* root)
{
    if(ac_search(root , req->uri , "URI") == 1) return 1;
    if(req->body && ac_search(root , req->body , "BODY") == 1) return 1;
    for(int i = 0 ; i < req->header_count ;i++)
        if(ac_search(root , req->headers[i].value , "HEADER") == 1) return 1;
    return 0;
}

int inspect_traffic(connection_t *conn , waf_rules_t *rules , ac_node_t* root)
{
    if(conn  == NULL)
        return -1;
    
    if(rules == NULL)
        return -1;

    
    http_request_t req;
    memset(&req , 0 , sizeof(http_request_t));

    if((parse_http_request(conn->client_buffer , &req)) < 0)
    {
        printf("Error Parsing the request");
        return -1;
    }

    int verdict = check_conn(&req , root);
    
    free_http_request(&req);

    return verdict;
}
