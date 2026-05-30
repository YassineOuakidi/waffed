#ifndef LOGGER_H
#define LOGGER_H

#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include "../dfa/dfa_common.h"
#include "../rules/lexer.h"


typedef struct logger{
    int logs_fd;
    char log_filename[128];
}logger_t;


void logger_init(logger_t *logger , const char *log_filename);

void insert_ac_blocked_log_line(logger_t* logger , int score);
void insert_dfa_blocked_log_line(logger_t* logger , detection_t detected ,char *buff , int len);
void insert_bad_request(logger_t* logger , char *req_buffer , int req_len);
void write_to_log(logger_t* logger , char *buf);

#endif