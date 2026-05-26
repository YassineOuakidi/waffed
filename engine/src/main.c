// main.c

#include <stdio.h>
#include <stdlib.h> 
#include <unistd.h> 
#include "../include/net/socket.h"
#include "../include/core/event_loop.h"
#include "../include/rules/aho_corasick.h"

int main()
{
    printf("[+] WAF Engine Starting...\n");

    int sockfd = create_listener_socket(3232);
    if(sockfd < 0)
    {
        printf("[-] FATAL: Failed to bind to port 3232. Is another service using it?\n");
        return EXIT_FAILURE; 
    }
    printf("[+] Successfully bound listener socket on port 3232.\n");

    waf_rules_t *rules = load_rules("../rules/disabled/experimental.rules");
    if(rules == NULL)
    {
        printf("[-] FATAL: Failed to load WAF rules. Shutting down.\n");
        close(sockfd);
        return EXIT_FAILURE;
    }

    ac_node_t *root = ac_create_node();
    if(root == NULL)
    {
        printf("[-] FATAL: Memory allocation for WAF engine failed.\n");
        free_rules(rules);
        close(sockfd);
        return EXIT_FAILURE;
    }

    ac_insert(root, rules);
    printf("[+] WAF Engine armed and ready. Entering Event Loop...\n");

    start_loop_event(sockfd, rules, root);
    
    printf("\n[!] Shutting down WAF gracefully...\n");
    ac_free(root);
    free_rules(rules);
    close(sockfd);

    return EXIT_SUCCESS;
}