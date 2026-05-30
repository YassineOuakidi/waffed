#ifndef RULE_ENGINE_H
#define RULE_ENGINE_H

#include <stdio.h>
#include <string.h>
#include "../core/connection.h"
#include "rule_loader.h"
#include "../http/http_parser.h"
#include "aho_corasick.h"
#include "../dfa/dfa_common.h"
#include "../logging/logger.h"
#include "../config/config_loader.h"

typedef enum verdict{
    VERDICT_DROP,
    VERDICT_ALLOW,
    VERDICT_BAD_REQ
}verdict_t;

verdict_t inspect_traffic(connection_t *conn , waf_rules_t *rules , ac_node_t* root , logger_t *logger , waf_config_t *config);

#endif
