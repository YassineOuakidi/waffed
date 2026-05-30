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

verdict_t inspect_traffic(connection_t *conn , waf_rules_t *rules , ac_node_t* root)
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
        return -1;
    }

    int score = check_conn(&req , root);

    verdict_t verdict;

    if(score >=100)
    {
        verdict = VERDICT_DROP;
        free_http_request(&req);
    }
    else if(score < 100 && score > 0)
    {
        lexer_t lx;
        //checking uri
        lexer_init(&lx , req.uri , strlen(req.uri) ,ZONE_URI);
        if(check_sqli(&lx))
        {
            free_http_request(&req);
            return VERDICT_DROP;
        }
        if(req.body)
        {
            lexer_init(&lx , req.body , strlen(req.body) , ZONE_BODY);
            if(check_sqli(&lx))
            {
                free_http_request(&req);
                return VERDICT_DROP;
            }
        }
    }
    
    free_http_request(&req);
    return VERDICT_ALLOW;
}
