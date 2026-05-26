

#include "../../include/http/http_parser.h"


//first we identify the pipeline 
//1. ascii_decode
//2. unicode_decode
//4. multiple_slash_norm
//5. backslash replacement
//6. High ascii Detection

void decoder(char *src)
{
    char hex[3];
    int i = 0;
    int j = 0;

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
            j++;
            i+=jump;
        }
        else if(src[i] == '+')
        {
            src[j] = ' ';
            i++;j++;
        }
        else
        {
            src[j] = tolower((unsigned char)src[i]);
            i++; j++;
        }
    }
    src[j] = '\0';
}

void decode_ascii(http_request_t *req)
{
    //first we proces the uri
    decoder(req->uri);
    
    //then we process the body
    if(req->body != NULL)
        decoder(req->body);

    //then we process headers values
    for(int i = 0 ; i < req->header_count ; i++)
    {
        decoder(req->headers[i].value);
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
