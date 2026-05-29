// http_parser.c


#include "../../include/http/http_parser.h"


int parse_http_request(char *raw_buffer, http_request_t *req)
{

	int result = sscanf(raw_buffer , "%15s %2047s %15s\r\n" , req->method , req->uri , req->version);
    if (result != 3)
        return -1;

    if (strncmp(req->version, "HTTP/", 5) != 0)
        return -1;

    char *crlf = strstr(raw_buffer , "\r\n\r\n");

    if(crlf == NULL)
    {
        req->header_count = 0;
        req->body = NULL;
        return -1;
    }

    req->header_count = 0;
    
    char *current_line = strstr(raw_buffer, "\r\n");
    if (current_line != NULL) {
        current_line += 2; 
    }

    while (current_line != NULL && current_line < crlf)
    {
        if(req->header_count >= 100)
        {
            free_http_request(req);
            return -1;
        }
        char *end_of_line = strstr(current_line, "\r\n");
        if (end_of_line == NULL || end_of_line > crlf) break;

        char *colon = NULL;
        for (char *p = current_line; p < end_of_line; p++) {
            if (*p == ':') {
                colon = p;
                break;
            }
        }
        if (colon == NULL)
        {
            free_http_request(req);
            return -1;
        }

        size_t key_len = colon - current_line;

        if (key_len == 0)
        {
            free_http_request(req);
            return -1;
        }

        req->headers[req->header_count].name = strndup(current_line, key_len);

        char *value_start = colon + 1;

        while (value_start < end_of_line && (*value_start == ' ' || *value_start == '\t')) {
            value_start++;
        }

        size_t val_len = end_of_line - value_start;
        req->headers[req->header_count].value = strndup(value_start, val_len);

        if (req->headers[req->header_count].name == NULL || req->headers[req->header_count].value == NULL)
        {
            free_http_request(req);
            return -1;
        }

        req->header_count++;

        current_line = end_of_line + 2;
    }


    if(crlf == NULL)
    {
        req->body = NULL;
    }
    else
    {
        req->body = strdup(crlf + 4);
    }

    normalize(req);

	return 0;
}

void free_http_request(http_request_t* req)
{
    if(req == NULL) return;

    for(int i = 0 ; i < req->header_count ; i++)
    {
        if(req->headers[i].name)
        {
            free(req->headers[i].name);
            req->headers[i].name = NULL;
        }

        if(req->headers[i].value)
        {
            free(req->headers[i].value);
            req->headers[i].value = NULL;
        }
    }

    req->header_count = 0;

    if(req->body)
    {
        free(req->body);
        req->body = NULL;
    }
}