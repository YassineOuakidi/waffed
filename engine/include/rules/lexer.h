#ifndef LEXER_H
#define LEXER_H


#define CC_WORD    (1 << 0) // 0x01
#define CC_DIGIT   (1 << 1) // 0x02
#define CC_SPACE   (1 << 2) // 0x04
#define CC_QUOTE   (1 << 3) // 0x08
#define CC_SPECIAL (1 << 4) // 0x10

typedef enum{
    TOK_EOF,
    TOK_NEED_MORE,
    TOK_WORD,
    TOK_QUOTE,
    TOK_NUMBER,
    TOK_EQUALS,
    TOK_OTHER
} token_kind_t;

typedef enum {
    ZONE_NONE = 0,
    ZONE_URI = 1 << 0,
    ZONE_QUERY = 1 << 1,
    ZONE_HEADER = 1 << 2,
    ZONE_BODY = 1 << 3
} waf_zone_t;

typedef enum{
    LEX_OK,
    LEX_EOF,
    LEX_ERROR
}lex_status_t;

typedef struct token{
    const char *start;
    int len;
    token_kind_t tok;
    waf_zone_t zone;
} token_t;

typedef struct lexer{
    const char *base;
    char *cur;
    const char *end;
    waf_zone_t zone;
}lexer_t;


void lexer_init(lexer_t *lx , const char *start , unsigned int len , waf_zone_t zone);
lex_status_t lexer_next(lexer_t *lx , token_t *out);


#endif