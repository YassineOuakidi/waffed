//aho_corasick.c

#include "../../include/rules/aho_corasick.h"


static int zone_matches(const char *rule_zone,
                        const char *expected_zone,
                        const char *header_name)
{
    if (rule_zone == NULL || expected_zone == NULL)
        return 0;

    if (strcasecmp(rule_zone, "ANY") == 0)
        return 1;

    if (strcasecmp(rule_zone, expected_zone) == 0)
        return 1;

    if (strcasecmp(expected_zone, "HEADER") == 0 &&
        strncasecmp(rule_zone, "HEADER:", 7) == 0 &&
        header_name != NULL)
    {
        return strcasecmp(rule_zone + 7, header_name) == 0;
    }

    return 0;
}

q_t *create_queue()
{
    q_t *q = calloc(1 , sizeof(q_t));
    q->head = 0;
    q->len = 0;
    q->tail = 0;
    return q;
}

void enqueue(q_t *q , ac_node_t *node)
{
    q->arr[q->tail] = node;
    q->tail++;
    q->len++;
}

ac_node_t* dequeue(q_t *q)
{
    ac_node_t* tmp = q->arr[q->head];
    q->head++;
    q->len--;
    return tmp;
}

int isEmpty(q_t* q)
{
    if(q->len > 0)
        return -1;
    return 0;
}

ac_node_t *ac_create_node()
{
    ac_node_t *new_node = calloc(1 , sizeof(ac_node_t));
    new_node->rule = NULL;
    return new_node;
}

void ac_insert(ac_node_t* root , waf_rules_t* rules)
{
    int index = 0;
    ac_node_t *node_ptr = root;

    for(int i = 0 ; i < rules->count ; i++)
    {
        index = 0; node_ptr = root;
        while(rules->rules[i].match_string[index])
        {
            if(!node_ptr->children[(unsigned char)rules->rules[i].match_string[index]])
                node_ptr->children[(unsigned char)rules->rules[i].match_string[index]] = ac_create_node();

            node_ptr = node_ptr->children[(unsigned char)rules->rules[i].match_string[index]];
            index++;
        }
        node_ptr->rule = &(rules->rules[i]);
    }
    ac_build_failure_links(root);
}

void ac_build_failure_links(ac_node_t* root)
{
    q_t* q = create_queue();

    ac_node_t* node_ptr = root;
    node_ptr->fail = root;
    for(int i = 0 ; i < 256 ; i++)
        if(node_ptr->children[i])
        {
            node_ptr->children[i]->fail = root;
            enqueue(q , node_ptr->children[i]);
        }
    
    while(isEmpty(q) == -1)
    {
        ac_node_t* current_node = dequeue(q);
        for(int i = 0 ; i < 256 ; i++)
        {
            if(current_node->children[i])
            {
                node_ptr = current_node->fail;
                while(node_ptr != root && node_ptr->children[i] == NULL)
                    node_ptr = node_ptr->fail;
                if(node_ptr->children[i] != NULL) current_node->children[i]->fail = node_ptr->children[i];
                else                              current_node->children[i]->fail = root;
                enqueue(q , current_node->children[i]);
            }
        }
    }
    free(q);
}

int ac_search(ac_node_t *root, char *buff , const char* expected_zone , const char *header_name)
{
    if (buff == NULL || root == NULL) return 0; 

    ac_node_t *current_node = root;
    int i = 0;

    int accumulated_score = 0;

    while (buff[i])
    {
        unsigned char c = (unsigned char)buff[i];

        while (current_node != root && current_node->children[c] == NULL)
        {
            current_node = current_node->fail;
        }

        if (current_node->children[c] != NULL)
        {
            current_node = current_node->children[c];
        }
        else
        {
            current_node = root;
        }

        ac_node_t *temp = current_node;
        while (temp != root)
        {
            if (temp->rule != NULL && zone_matches(temp->rule->zone, expected_zone, header_name))
            {
                printf("WAF BLOCK: Rule ID '%s' triggered in URI! Match: '%s'\n", 
                       temp->rule->id, 
                       temp->rule->match_string);
                accumulated_score += temp->rule->score; 
            }
            temp = temp->fail;
        }
        i++;
    }

    return accumulated_score; 
}

void ac_free(ac_node_t *node)
{
    if (node == NULL) return;

    for (int i = 0; i < 256; i++)
    {
        if (node->children[i] != NULL)
        {
            ac_free(node->children[i]);
        }
    }

    free(node);
}
