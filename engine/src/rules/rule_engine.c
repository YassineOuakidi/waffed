//rule_engine.c

#include "../../include/rules/rule_engine.h"

int check_conn(http_request_t* req , ac_node_t* root)
{
    int score = 0;
    score += ac_search(root, req->uri, "URI", NULL);

    if(req->body)
        score += ac_search(root , req->body , "BODY" , NULL);
    
    for(int i = 0 ; i < req->header_count ;i++)
        score += ac_search(root , req->headers[i].value , "HEADER" , req->headers[i].name);

    return score;
}

verdict_t inspect_traffic(connection_t *conn , waf_rules_t *rules , ac_node_t* root , logger_t* logger , waf_config_t *config)
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
        free_http_request(&req);
        insert_bad_request(logger , conn->client_buffer , conn->client_buffer_len);
        return VERDICT_BAD_REQ;
    }

    int score = check_conn(&req , root);
    
    if(score >= config->block_threshold)
    {
        free_http_request(&req);
        insert_ac_blocked_log_line(logger , score);
        return VERDICT_DROP;
    }

    detection_t reason = run_dfas(&req);
    if(reason != CLEAN_REQUEST)
    {
        insert_dfa_blocked_log_line(logger , reason , conn->client_buffer , conn->client_buffer_len);
        free_http_request(&req);
        return VERDICT_DROP;
    }

    free_http_request(&req);
    return VERDICT_ALLOW;
}
