#include "../../include/rules/rule_loader.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

int parse_rule_line(rule_t *ruleItem, char *buff)
{
    if (buff[0] == '\0' || buff[0] == '#') return -1;

    char *saveptr;
    char *token;

    token = strtok_r(buff, "|", &saveptr);
    if (token == NULL) return -1;
    char *id_tmp = strdup(token);

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { free(id_tmp); return -1; }
    char *action_tmp = strdup(token);

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { free(id_tmp); free(action_tmp); return -1; }
    char *zone_tmp = strdup(token);

    token = strtok_r(NULL, "|", &saveptr);
    if (token == NULL) { free(id_tmp); free(action_tmp); free(zone_tmp); return -1; }
    char *match_tmp = strdup(token);

    ruleItem->id = id_tmp;
    ruleItem->action = action_tmp;
    ruleItem->zone = zone_tmp;
    ruleItem->match_string = match_tmp;

    return 0;
}

waf_rules_t* load_rules(const char *filepath)
{
    FILE* f = fopen(filepath, "r");
    if (f == NULL)
    {
        printf("error: Could not open rule file: %s\n", filepath);
        return NULL;
    }

    waf_rules_t *r = malloc(sizeof(waf_rules_t));
    if (r == NULL) { fclose(f); return NULL; }

    int capacity = 10;
    r->rules = malloc(capacity * sizeof(rule_t));
    if (r->rules == NULL) { free(r); fclose(f); return NULL; }
    r->count = 0;

    size_t n = 0;
    char *buff = NULL;
    ssize_t read;

    while ((read = getline(&buff, &n, f)) != -1)
    {
        buff[strcspn(buff, "\r\n")] = '\0';

        if (parse_rule_line(&(r->rules[r->count]), buff) == 0)
        {
            r->count++;

            if (r->count >= capacity)
            {
                capacity *= 2;
                rule_t *temp = realloc(r->rules, capacity * sizeof(rule_t));
                if (temp == NULL)
                {
                    printf("memory reallocation faile loaded %d rules.\n", r->count);
                    break; 
                }
                r->rules = temp;
            }
        }
    }

    free(buff);
    fclose(f);
    return r;
}

void free_rules(waf_rules_t* rules)
{
    if (rules == NULL) return;

    for (int i = 0; i < rules->count; i++)
    {
        if (rules->rules[i].id) free(rules->rules[i].id);
        if (rules->rules[i].action) free(rules->rules[i].action);
        if (rules->rules[i].zone) free(rules->rules[i].zone);
        if (rules->rules[i].match_string) free(rules->rules[i].match_string);
    }

    if (rules->rules) free(rules->rules);
    free(rules);
}