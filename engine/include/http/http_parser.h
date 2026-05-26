#ifndef HTTP_PARSER_H
#define HTTP_PARSER_H

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct {
    char *name;
    char *value;
} http_header_t;

typedef struct {
    char method[16];
    char uri[2048];
    char version[16];
    http_header_t headers[100];
    int header_count;
    char *body;
} http_request_t;

int parse_http_request(char *raw_buffer, http_request_t *req);
void normalize(http_request_t *req);
void free_http_request(http_request_t* req);

#endif
