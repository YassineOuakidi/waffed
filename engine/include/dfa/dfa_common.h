#ifndef DFA_COMMON_H
#define DFA_COMMON_H

#include "../http/http_parser.h"

typedef enum {
    SQLI_DETECTED,
    XSS_DETECTED,
    CLEAN_REQUEST
    //more features will be added soon
}detection_t ;

detection_t run_dfas(http_request_t *req);

#endif