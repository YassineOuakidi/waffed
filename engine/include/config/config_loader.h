#ifndef CONFIG_LOADER_H
#define CONFIG_LOADER_H

#define CONFIG_PATH_MAX 256
#define CONFIG_HOST_MAX 64

typedef struct waf_config {
    int listen_port;

    char backend_host[CONFIG_HOST_MAX];
    int backend_port;

    char rules_file[CONFIG_PATH_MAX];
    int block_threshold;

    int enable_sql_dfa;
    int enable_xss_dfa;

    char log_file[CONFIG_PATH_MAX];
    int log_allow;

    int max_request_size;
    int max_body_size;
    int max_headers;
} waf_config_t;

void config_set_defaults(waf_config_t *cfg);
int load_config(const char *path, waf_config_t *cfg);
void print_config(const waf_config_t *cfg);

#endif