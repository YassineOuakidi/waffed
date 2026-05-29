#ifndef AHO_CORASICK_H
#define AHO_CORASICK_H

#include "rule_loader.h"
#include "../http/http_parser.h"
#include "../rules/rule_loader.h"
#include <string.h>


typedef struct aho_corasick_node{
    struct aho_corasick_node *children[256];
    struct aho_corasick_node *fail;
    rule_t *rule;
} ac_node_t;

typedef struct queue{
    ac_node_t *arr[65536];
    int len;
    int head;
    int tail;
}q_t;

ac_node_t* ac_create_node();
void ac_insert(ac_node_t* root , waf_rules_t* rules);
int ac_search(ac_node_t* root, char* buffer, const char* expected_zone , const char *header_name);
void ac_build_failure_links(ac_node_t* root);
void ac_free(ac_node_t *node);

#endif
