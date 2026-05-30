//logger.x

#include "../../include/logging/logger.h"

#include <stdio.h>
#include <time.h>
#include <errno.h>

#define LOG_LINE_MAX 4096
#define LOG_PAYLOAD_MAX 1024


static void get_attack(char *buf , detection_t detected)
{
    if(detected == SQLI_DETECTED)
        snprintf(buf , 64 , "%s" , "SQLI_DFA");
    else if(detected == XSS_DETECTED)
        snprintf(buf , 64 ,"%s" , "XSS_DFA");
}

static void write_all(int fd, const char *buf, size_t len)
{
    size_t written = 0;

    while (written < len)
    {
        ssize_t ret = write(fd, buf + written, len - written);

        if (ret < 0)
        {
            if (errno == EINTR)
                continue;

            return;
        }

        if (ret == 0)
            return;

        written += (size_t)ret;
    }
}

static void current_timestamp(char *buf, size_t buf_size)
{
    time_t now = time(NULL);
    struct tm tm_now;

    if (localtime_r(&now, &tm_now) == NULL)
    {
        snprintf(buf, buf_size, "unknown-time");
        return;
    }

    strftime(buf, buf_size, "%Y-%m-%d %H:%M:%S", &tm_now);
}

static int sanitize_payload(const char *src, int src_len, char *dst, int dst_size)
{
    int j = 0;

    if (src == NULL || src_len <= 0 || dst == NULL || dst_size <= 0)
    {
        if (dst_size > 0)
            dst[0] = '\0';

        return 0;
    }

    for (int i = 0; i < src_len && j < dst_size - 1; i++)
    {
        char c = src[i];

        if (c == '\n' || c == '\r' || c == '\t')
        {
            if (j < dst_size - 2)
            {
                dst[j++] = ' ';
            }
        }
        else if ((unsigned char)c < 32 || (unsigned char)c > 126)
        {
            if (j < dst_size - 2)
            {
                dst[j++] = '.';
            }
        }
        else
        {
            dst[j++] = c;
        }
    }

    dst[j] = '\0';
    return j;
}

void logger_init(logger_t *logger, const char *log_filename)
{
    if (logger == NULL)
        return;

    memset(logger, 0, sizeof(*logger));
    logger->logs_fd = -1;

    if (log_filename == NULL || log_filename[0] == '\0')
        log_filename = "waf.log";

    strncpy(logger->log_filename, log_filename, sizeof(logger->log_filename) - 1);
    logger->log_filename[sizeof(logger->log_filename) - 1] = '\0';

    logger->logs_fd = open(
        logger->log_filename,
        O_WRONLY | O_CREAT | O_APPEND,
        0644
    );
}

void write_to_log(logger_t *logger, char *buf)
{
    if (logger == NULL || buf == NULL)
        return;

    if (logger->logs_fd < 0)
        return;

    write_all(logger->logs_fd, buf, strlen(buf));
}

void insert_ac_blocked_log_line(logger_t *logger, int score)
{
    char timestamp[64];
    char line[LOG_LINE_MAX];

    if (logger == NULL || logger->logs_fd < 0)
        return;

    current_timestamp(timestamp, sizeof(timestamp));

    snprintf(
        line,
        sizeof(line),
        "[%s] DROP reason=AC_SCORE_THRESHOLD score=%d\n",
        timestamp,
        score
    );

    write_to_log(logger, line);
    fsync(logger->logs_fd);
}

void insert_dfa_blocked_log_line(logger_t *logger, detection_t detected , char *buff, int len)
{
    char timestamp[64];
    char attack_detected[64];
    char payload[LOG_PAYLOAD_MAX];
    char line[LOG_LINE_MAX];

    if (logger == NULL || logger->logs_fd < 0)
        return;

    current_timestamp(timestamp, sizeof(timestamp));
    sanitize_payload(buff, len, payload, sizeof(payload));
    get_attack(attack_detected , detected);


    snprintf(
        line,
        sizeof(line),
        "[%s] DROP reason=%s payload=\"%s\"\n",
        timestamp,
        attack_detected,
        payload
    );

    write_to_log(logger, line);
    fsync(logger->logs_fd);
}

void insert_bad_request(logger_t *logger, char *req_buffer, int req_len)
{
    char timestamp[64];
    char payload[LOG_PAYLOAD_MAX];
    char line[LOG_LINE_MAX];

    if (logger == NULL || logger->logs_fd < 0)
        return;

    current_timestamp(timestamp, sizeof(timestamp));
    sanitize_payload(req_buffer, req_len, payload, sizeof(payload));

    snprintf(
        line,
        sizeof(line),
        "[%s] BAD_REQ reason=MALFORMED_HTTP payload=\"%s\"\n",
        timestamp,
        payload
    );

    write_to_log(logger, line);
    fsync(logger->logs_fd);
}