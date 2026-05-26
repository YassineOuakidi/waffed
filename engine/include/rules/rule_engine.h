#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stdio.h>
#include <string.h>
#include "../core/connection.h"
#include "rule_loader.h"
#include "../http/http_parser.h"
#include "aho_corasick.h"

int inspect_traffic(connection_t *conn , waf_rules_t *rules , ac_node_t* root);

#endif
