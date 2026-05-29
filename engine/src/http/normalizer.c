

#include "../../include/http/http_parser.h"


//first we identify the pipeline 
//1. ascii_decode
//2. multiple_slash_norm
//3. backslash replacement

int decoder(char *src)
{
    char hex[3];
    int i = 0;
    int j = 0;
    int changed = 0;

    while(src[i])
    {
        if((src[i] == '$'|| src[i] == '%') && src[i + 1] && src[i+2])
        {
            int first , second , jump;
            if(isxdigit(src[i+1]) && isxdigit(src[i+2]))
            {
                first = i+1;
                second = i+2;
                jump = 3;
            }
            else if((src[i+1] == 'u' || src[i+1] == 'U' ) && src[i+3] && src[i+4] && src[i+5] && isxdigit(src[i+4]) && isxdigit(src[i+5]))
            {
                first = i+4;
                second = i+5;
                jump = 6;
            }
            else
            {
                src[j] = tolower((unsigned char)src[i]);
                j++; i++;
                continue;
            }
            hex[0] = src[first];
            hex[1] = src[second];
            hex[2] = '\0';
            unsigned char decoded = (unsigned char)strtol(hex, NULL, 16);
            if (decoded == '\0') decoded = ' ';
            src[j] = tolower(decoded);
            changed = 1;
            j++;
            i+=jump;
        }
        else if(src[i] == '+')
        {
            src[j] = ' ';
            i++;j++;
            changed = 1;
        }
        else
        {
            src[j] = tolower((unsigned char)src[i]);
            i++; j++;
        }
    }
    src[j] = '\0';
    return changed;
}

static void decode_repeated(char *src)
{
    if (src == NULL)
        return;

    for (int pass = 0; pass < 4; pass++)
    {
        int changed = decoder(src);

        if (!changed)
            break;
    }
}

void decode_ascii(http_request_t *req)
{
    //first we proces the uri
    decode_repeated(req->uri);
    
    //then we process the body
    if(req->body != NULL)
        decode_repeated(req->body);

    //then we process headers values
    for(int i = 0 ; i < req->header_count ; i++)
    {
        decode_repeated(req->headers[i].value);
    }
    
}

void merge_slash(char *str)
{
    int i = 0;
    int j = 0;

    while(str[i])
    {
        if(str[i] == '\\')
            str[i] = '/';

        if(str[i] == '/' && j>0 && str[j-1] == '/')
        {
            i++;
        }
        else
        {
            str[j] = str[i];
            i++;j++;
        }
    }
    str[j] = '\0';
}

void slash_handler(http_request_t *req)
{

    merge_slash(req->uri);
    for(int i = 0 ; i < req->header_count ; i++)
        merge_slash(req->headers[i].value);
}


void normalize(http_request_t* req)
{
    decode_ascii(req);
    slash_handler(req);
}

void normalize_rule_pattern(char *s, const char *zone)
{
    if (s == NULL)
        return;

    decode_repeated(s);

    if (zone == NULL || strncmp(zone, "BODY", 4) != 0)
        merge_slash(s);
}