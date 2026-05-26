#ifndef RULE_LOADER_H
#define RULE_LOADER_H

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>


typedef struct rule{
    char* id;
    char* action;
    char* zone;
    char* match_string;
} rule_t;

typedef struct {
    rule_t *rules;
    int count;
} waf_rules_t;

waf_rules_t *load_rules(const char *filepath);
void free_rules(waf_rules_t *rules);

#endif
