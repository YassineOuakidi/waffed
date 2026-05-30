#include "../../include/rules/lexer.h"

static const unsigned char char_class[256] = {
    ['a' ... 'z'] = CC_WORD,
    ['A' ... 'Z'] = CC_WORD,
    ['_'] = CC_WORD,
    
    ['0' ... '9'] = CC_DIGIT,
    
    [' ']  = CC_SPACE,
    ['\t'] = CC_SPACE,
    ['\r'] = CC_SPACE,
    ['\n'] = CC_SPACE,

    ['\''] = CC_QUOTE,
    ['"']  = CC_QUOTE,

    ['='] = CC_SPECIAL,
    ['<'] = CC_SPECIAL,
    ['>'] = CC_SPECIAL,
    ['!'] = CC_SPECIAL,
    [';'] = CC_SPECIAL,
    ['/'] = CC_SPECIAL,
    ['*'] = CC_SPECIAL,
    ['-'] = CC_SPECIAL,
    ['#'] = CC_SPECIAL,
    ['('] = CC_SPECIAL,
    [')'] = CC_SPECIAL,
    [','] = CC_SPECIAL
};

static token_t make_token(lexer_t *lx , const char* token_start , token_kind_t kind)
{
    token_t tok;
    tok.start = token_start;
    tok.len = (int)(lx->cur - token_start);
    tok.kind = kind;
    tok.zone = lx->zone;
    return tok;
}

static inline unsigned char advance(lexer_t *lx)
{
    unsigned char byte = *(lx->cur); 
    lx->cur++;
    return byte;   
}

static inline unsigned char peek(lexer_t *lx)
{
    if(lx->cur == lx->end) return '\0';
    return *(lx->cur);
}

static void skip_whitespace(lexer_t *lx)
{
    while (lx->cur < lx->end &&
           (char_class[(unsigned char)*lx->cur] & CC_SPACE))
    {
        lx->cur++;
    }
}


void lexer_init(lexer_t* lx , const char *start , unsigned int len , waf_zone_t zone)
{
    lx->base = start;
    lx->cur = lx->base;
    lx->end = (start + len);
    lx->zone = zone;
}


lex_status_t lexer_next(lexer_t *lx, token_t *out)
{
    skip_whitespace(lx);

    if (lx->cur >= lx->end)
    {
        *out = make_token(lx, lx->cur, TOK_EOF);
        return LEX_EOF;
    }

    const char *token_start = lx->cur;
    unsigned char c = advance(lx);
    unsigned char cls = char_class[c];

    if (cls & CC_DIGIT)
    {
        while (lx->cur < lx->end)
        {
            unsigned char next_c = (unsigned char)*lx->cur;

            if (!(char_class[next_c] & CC_DIGIT))
                break;

            lx->cur++;
        }

        *out = make_token(lx, token_start, TOK_NUMBER);
        return LEX_OK;
    }

    if (cls & CC_WORD)
    {
        while (lx->cur < lx->end)
        {
            unsigned char next_c = (unsigned char)*lx->cur;

            if (!((char_class[next_c] & CC_WORD) ||
                  (char_class[next_c] & CC_DIGIT)))
                break;

            lx->cur++;
        }

        *out = make_token(lx, token_start, TOK_WORD);
        return LEX_OK;
    }

    if (cls & CC_QUOTE)
    {
        *out = make_token(lx, token_start, TOK_QUOTE);
        return LEX_OK;
    }

    if (c == '=')
    {
        *out = make_token(lx, token_start, TOK_EQUALS);
        return LEX_OK;
    }

    if (c == '-' && lx->cur < lx->end && *lx->cur == '-')
    {
        lx->cur++;
        *out = make_token(lx, token_start, TOK_OTHER);
        return LEX_OK;
    }

    if (c == '/' && lx->cur < lx->end && *lx->cur == '*')
    {
        lx->cur++;
        *out = make_token(lx, token_start, TOK_OTHER);
        return LEX_OK;
    }

    if ((c == '!' || c == '<' || c == '>') &&
        lx->cur < lx->end &&
        (*lx->cur == '=' || (c == '<' && *lx->cur == '>')))
    {
        lx->cur++;
        *out = make_token(lx, token_start, TOK_OTHER);
        return LEX_OK;
    }

    *out = make_token(lx, token_start, TOK_OTHER);
    return LEX_OK;
}