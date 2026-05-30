#include "../../include/dfa/dfa_common.h"
#include "../../include/dfa/sql_dfa.h"
#include "../../include/dfa/js_dfa.h"

#include <string.h>


static detection_t run_dfas_on_buffer(const char *buf, waf_zone_t zone)
{
    lexer_t lx;

    if (buf == NULL)
        return CLEAN_REQUEST;

    lexer_init(&lx, buf, strlen(buf), zone);

    if (check_sqli(&lx))
        return SQLI_DETECTED;

    lexer_init(&lx, buf, strlen(buf), zone);

    if (check_js(&lx))
        return XSS_DETECTED;

    return CLEAN_REQUEST;
}

detection_t run_dfas(http_request_t *req)
{
    if (req == NULL)
        return CLEAN_REQUEST;

    detection_t detection;
    
    detection = run_dfas_on_buffer(req->uri , ZONE_URI);
    if (detection != CLEAN_REQUEST)
        return detection;

    detection = run_dfas_on_buffer(req->body , ZONE_BODY);
    if (detection != CLEAN_REQUEST)
        return detection;

    for (int i = 0; i < req->header_count; i++)
    {
        detection = run_dfas_on_buffer(req->headers[i].value , ZONE_HEADER);
        if (detection != CLEAN_REQUEST)
            return detection;
    }

    return detection;
}