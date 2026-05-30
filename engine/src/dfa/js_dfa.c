#include "../../include/dfa/js_dfa.h"

#include <string.h>
#include <strings.h>

static int tok_equals_ci(const token_t *tok, const char *s)
{
    int len = (int)strlen(s);

    if (tok->len != len)
        return 0;

    return strncasecmp(tok->start, s, len) == 0;
}

// js_classify is AI Generated
js_class_t js_classify(const token_t *tok)
{
    switch (tok->kind)
    {
        case TOK_QUOTE:
            return JS_C_QUOTE;

        case TOK_EQUALS:
            return JS_C_EQUALS;

        case TOK_WORD:
            if (tok_equals_ci(tok, "script"))
                return JS_C_SCRIPT;

            if (tok_equals_ci(tok, "iframe") ||
                tok_equals_ci(tok, "object") ||
                tok_equals_ci(tok, "embed") ||
                tok_equals_ci(tok, "svg") ||
                tok_equals_ci(tok, "math"))
                return JS_C_DANGEROUS_TAG;

            if (tok_equals_ci(tok, "onload") ||
                tok_equals_ci(tok, "onerror") ||
                tok_equals_ci(tok, "onclick") ||
                tok_equals_ci(tok, "onmouseover") ||
                tok_equals_ci(tok, "onmouseenter") ||
                tok_equals_ci(tok, "onfocus") ||
                tok_equals_ci(tok, "onblur") ||
                tok_equals_ci(tok, "onsubmit") ||
                tok_equals_ci(tok, "onchange") ||
                tok_equals_ci(tok, "oninput") ||
                tok_equals_ci(tok, "onkeyup") ||
                tok_equals_ci(tok, "onkeydown"))
                return JS_C_EVENT_HANDLER;

            if (tok_equals_ci(tok, "javascript") ||
                tok_equals_ci(tok, "vbscript"))
                return JS_C_JS_SCHEME;

            if (tok_equals_ci(tok, "data"))
                return JS_C_DATA_SCHEME;

            if (tok_equals_ci(tok, "alert") ||
                tok_equals_ci(tok, "eval") ||
                tok_equals_ci(tok, "prompt") ||
                tok_equals_ci(tok, "confirm") ||
                tok_equals_ci(tok, "setTimeout") ||
                tok_equals_ci(tok, "setInterval") ||
                tok_equals_ci(tok, "Function"))
                return JS_C_DANGEROUS_FUNC;

            if (tok_equals_ci(tok, "document") ||
                tok_equals_ci(tok, "window") ||
                tok_equals_ci(tok, "location") ||
                tok_equals_ci(tok, "self") ||
                tok_equals_ci(tok, "top") ||
                tok_equals_ci(tok, "parent"))
                return JS_C_DOM_OBJECT;

            if (tok_equals_ci(tok, "cookie") ||
                tok_equals_ci(tok, "write") ||
                tok_equals_ci(tok, "writeln") ||
                tok_equals_ci(tok, "innerHTML") ||
                tok_equals_ci(tok, "outerHTML") ||
                tok_equals_ci(tok, "insertAdjacentHTML") ||
                tok_equals_ci(tok, "href") ||
                tok_equals_ci(tok, "src") ||
                tok_equals_ci(tok, "assign") ||
                tok_equals_ci(tok, "replace"))
                return JS_C_DOM_SINK;

            return JS_C_WORD;

        case TOK_OTHER:
            if (tok->start[0] == '<')
                return JS_C_TAG_OPEN;

            if (tok->start[0] == '>')
                return JS_C_TAG_CLOSE;

            if (tok->start[0] == '/')
            {
                if (tok->len >= 2 && tok->start[1] == '*')
                    return JS_C_COMMENT;

                return JS_C_SLASH;
            }

            if (tok->start[0] == '(')
                return JS_C_PAREN_OPEN;

            if (tok->start[0] == ')')
                return JS_C_PAREN_CLOSE;

            if (tok->start[0] == '.')
                return JS_C_DOT;

            if (tok->start[0] == ':')
                return JS_C_COLON;

            return JS_C_OTHER;

        default:
            return JS_C_OTHER;
    }
}


// check the DFA png file 
int check_js(lexer_t *lx)
{
    token_t tok;
    js_state_t current_state = JS_S_START;

    while (lexer_next(lx, &tok) != LEX_EOF)
    {
        js_class_t cls = js_classify(&tok);

        switch (current_state)
        {
            case JS_S_START:
                if (cls == JS_C_TAG_OPEN)
                {
                    current_state = JS_S_SAW_TAG_OPEN;
                }
                else if (cls == JS_C_EVENT_HANDLER)
                {
                    current_state = JS_S_SAW_EVENT_HANDLER;
                }
                else if (cls == JS_C_JS_SCHEME)
                {
                    current_state = JS_S_SAW_JS_SCHEME;
                }
                else if (cls == JS_C_DATA_SCHEME)
                {
                    current_state = JS_S_SAW_DATA_SCHEME;
                }
                else if (cls == JS_C_DANGEROUS_FUNC)
                {
                    current_state = JS_S_SAW_DANGEROUS_FUNC;
                }
                else if (cls == JS_C_DOM_OBJECT)
                {
                    current_state = JS_S_SAW_DOM_OBJECT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_TAG_OPEN:
                if (cls == JS_C_SCRIPT)
                {
                    current_state = JS_S_ACCEPT;
                }
                else if (cls == JS_C_DANGEROUS_TAG)
                {
                    current_state = JS_S_SAW_DANGEROUS_TAG;
                }
                else if (cls == JS_C_WORD)
                {
                    current_state = JS_S_SAW_HTML_TAG;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_HTML_TAG:
                if (cls == JS_C_EVENT_HANDLER)
                {
                    current_state = JS_S_SAW_EVENT_HANDLER;
                }
                else if (cls == JS_C_JS_SCHEME)
                {
                    current_state = JS_S_SAW_JS_SCHEME;
                }
                else if (cls == JS_C_DATA_SCHEME)
                {
                    current_state = JS_S_SAW_DATA_SCHEME;
                }
                else if (cls == JS_C_TAG_CLOSE)
                {
                    current_state = JS_S_START;
                }
                else
                {
                    current_state = JS_S_SAW_HTML_TAG;
                }
                break;

            case JS_S_SAW_DANGEROUS_TAG:
                if (cls == JS_C_EVENT_HANDLER)
                {
                    current_state = JS_S_SAW_EVENT_HANDLER;
                }
                else if (cls == JS_C_JS_SCHEME)
                {
                    current_state = JS_S_SAW_JS_SCHEME;
                }
                else if (cls == JS_C_DATA_SCHEME)
                {
                    current_state = JS_S_SAW_DATA_SCHEME;
                }
                else if (cls == JS_C_TAG_CLOSE)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_SAW_DANGEROUS_TAG;
                }
                break;

            case JS_S_SAW_EVENT_HANDLER:
                if (cls == JS_C_EQUALS)
                {
                    current_state = JS_S_SAW_ATTR_EQUALS;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_ATTR_EQUALS:
                if (cls == JS_C_QUOTE ||
                    cls == JS_C_WORD ||
                    cls == JS_C_DANGEROUS_FUNC ||
                    cls == JS_C_JS_SCHEME)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_JS_SCHEME:
                if (cls == JS_C_COLON ||
                    cls == JS_C_DANGEROUS_FUNC)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_DATA_SCHEME:
                if (cls == JS_C_COLON)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_DANGEROUS_FUNC:
                if (cls == JS_C_PAREN_OPEN)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_DOM_OBJECT:
                if (cls == JS_C_DOT)
                {
                    current_state = JS_S_SAW_DOT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_DOT:
                if (cls == JS_C_DOM_SINK)
                {
                    current_state = JS_S_SAW_DOM_SINK;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_SAW_DOM_SINK:
                if (cls == JS_C_EQUALS ||
                    cls == JS_C_PAREN_OPEN)
                {
                    current_state = JS_S_ACCEPT;
                }
                else
                {
                    current_state = JS_S_START;
                }
                break;

            case JS_S_ACCEPT:
                return 1;

            default:
                current_state = JS_S_START;
                break;
        }

        if (current_state == JS_S_ACCEPT)
            return 1;
    }

    return 0;
}