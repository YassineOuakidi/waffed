#include "../../include/config/config_loader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

static char *trim_left(char *s)
{
    while (*s != '\0' && isspace((unsigned char)*s))
        s++;

    return s;
}

static void trim_right(char *s)
{
    size_t len = strlen(s);

    while (len > 0 && isspace((unsigned char)s[len - 1]))
    {
        s[len - 1] = '\0';
        len--;
    }
}

static char *trim(char *s)
{
    s = trim_left(s);
    trim_right(s);
    return s;
}

static int parse_int_value(const char *value, int *out)
{
    char *end = NULL;
    long parsed;

    if (value == NULL || out == NULL)
        return -1;

    errno = 0;
    parsed = strtol(value, &end, 10);

    if (errno != 0 || end == value)
        return -1;

    while (*end != '\0')
    {
        if (!isspace((unsigned char)*end))
            return -1;
        end++;
    }

    if (parsed < 0 || parsed > 2147483647L)
        return -1;

    *out = (int)parsed;
    return 0;
}

static int parse_bool_value(const char *value, int *out)
{
    if (value == NULL || out == NULL)
        return -1;

    if (strcmp(value, "1") == 0 ||
        strcmp(value, "true") == 0 ||
        strcmp(value, "yes") == 0 ||
        strcmp(value, "on") == 0)
    {
        *out = 1;
        return 0;
    }

    if (strcmp(value, "0") == 0 ||
        strcmp(value, "false") == 0 ||
        strcmp(value, "no") == 0 ||
        strcmp(value, "off") == 0)
    {
        *out = 0;
        return 0;
    }

    return -1;
}

static void copy_config_string(char *dst, size_t dst_size, const char *src)
{
    if (dst == NULL || dst_size == 0)
        return;

    if (src == NULL)
    {
        dst[0] = '\0';
        return;
    }

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

void config_set_defaults(waf_config_t *cfg)
{
    if (cfg == NULL)
        return;

    memset(cfg, 0, sizeof(*cfg));

    cfg->listen_port = 3232;

    copy_config_string(cfg->backend_host, sizeof(cfg->backend_host), "127.0.0.1");
    cfg->backend_port = 8000;

    copy_config_string(cfg->rules_file, sizeof(cfg->rules_file), "../rules/disabled/experimental.rules");
    cfg->block_threshold = 100;

    cfg->enable_sql_dfa = 1;
    cfg->enable_xss_dfa = 1;

    copy_config_string(cfg->log_file, sizeof(cfg->log_file), "../logs/waf.log");
    cfg->log_allow = 0;

    cfg->max_request_size = 8192;
    cfg->max_body_size = 8192;
    cfg->max_headers = 100;
}

int load_config(const char *path, waf_config_t *cfg)
{
    FILE *fp;
    char line[512];
    int line_no = 0;

    if (path == NULL || cfg == NULL)
        return -1;

    config_set_defaults(cfg);

    fp = fopen(path, "r");
    if (fp == NULL)
    {
        fprintf(stderr, "[-] Could not open config file: %s\n", path);
        return -1;
    }

    while (fgets(line, sizeof(line), fp) != NULL)
    {
        char *key;
        char *value;
        char *eq;

        line_no++;

        key = trim(line);

        if (key[0] == '\0' || key[0] == '#')
            continue;

        eq = strchr(key, '=');
        if (eq == NULL)
        {
            fprintf(stderr, "[-] Invalid config line %d: missing '='\n", line_no);
            fclose(fp);
            return -1;
        }

        *eq = '\0';
        value = eq + 1;

        key = trim(key);
        value = trim(value);

        if (strcmp(key, "listen_port") == 0)
        {
            if (parse_int_value(value, &cfg->listen_port) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "backend_host") == 0)
        {
            copy_config_string(cfg->backend_host, sizeof(cfg->backend_host), value);
        }
        else if (strcmp(key, "backend_port") == 0)
        {
            if (parse_int_value(value, &cfg->backend_port) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "rules_file") == 0)
        {
            copy_config_string(cfg->rules_file, sizeof(cfg->rules_file), value);
        }
        else if (strcmp(key, "block_threshold") == 0)
        {
            if (parse_int_value(value, &cfg->block_threshold) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "enable_sql_dfa") == 0)
        {
            if (parse_bool_value(value, &cfg->enable_sql_dfa) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "enable_xss_dfa") == 0)
        {
            if (parse_bool_value(value, &cfg->enable_xss_dfa) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "log_file") == 0)
        {
            copy_config_string(cfg->log_file, sizeof(cfg->log_file), value);
        }
        else if (strcmp(key, "log_allow") == 0)
        {
            if (parse_bool_value(value, &cfg->log_allow) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "max_request_size") == 0)
        {
            if (parse_int_value(value, &cfg->max_request_size) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "max_body_size") == 0)
        {
            if (parse_int_value(value, &cfg->max_body_size) != 0)
                goto invalid_value;
        }
        else if (strcmp(key, "max_headers") == 0)
        {
            if (parse_int_value(value, &cfg->max_headers) != 0)
                goto invalid_value;
        }
        else
        {
            fprintf(stderr, "[!] Unknown config key on line %d: %s\n", line_no, key);
        }
    }

    fclose(fp);
    return 0;

invalid_value:
    fprintf(stderr, "[-] Invalid value in config line %d\n", line_no);
    fclose(fp);
    return -1;
}

void print_config(const waf_config_t *cfg)
{
    if (cfg == NULL)
        return;

    printf("[+] Config loaded:\n");
    printf("    listen_port=%d\n", cfg->listen_port);
    printf("    backend_host=%s\n", cfg->backend_host);
    printf("    backend_port=%d\n", cfg->backend_port);
    printf("    rules_file=%s\n", cfg->rules_file);
    printf("    block_threshold=%d\n", cfg->block_threshold);
    printf("    enable_sql_dfa=%d\n", cfg->enable_sql_dfa);
    printf("    enable_xss_dfa=%d\n", cfg->enable_xss_dfa);
    printf("    log_file=%s\n", cfg->log_file);
    printf("    log_allow=%d\n", cfg->log_allow);
    printf("    max_request_size=%d\n", cfg->max_request_size);
    printf("    max_body_size=%d\n", cfg->max_body_size);
    printf("    max_headers=%d\n", cfg->max_headers);
}