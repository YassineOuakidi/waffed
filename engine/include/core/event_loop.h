#ifndef EVENT_LOOP_H
#define EVENT_LOOP_H

#include <sys/socket.h>
#include <sys/epoll.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include "connection.h"
#include "../http/http_parser.h"
#include "../net/backend.h"
#include "../rules/rule_loader.h"
#include "../rules/aho_corasick.h"
#include <pcre2.h>
#define PCRE2_CODE_UNIT_WIDTH 8

void start_loop_event(int listen_sock , waf_rules_t *rules , ac_node_t* root);

#endif
