#ifndef JS_DFA_H
#define JS_DFA_H

#include <stdint.h>
#include "../rules/lexer.h"

typedef enum {
    JS_C_OTHER = 0,

    JS_C_WORD,
    JS_C_QUOTE,
    JS_C_EQUALS,

    JS_C_TAG_OPEN,        
    JS_C_TAG_CLOSE,       
    JS_C_SLASH,           

    JS_C_PAREN_OPEN,      
    JS_C_PAREN_CLOSE,     
    JS_C_DOT,             
    JS_C_COLON,           

    JS_C_SCRIPT,          
    JS_C_DANGEROUS_TAG,   

    JS_C_EVENT_HANDLER,   
    JS_C_JS_SCHEME,       
    JS_C_DATA_SCHEME,     

    JS_C_DANGEROUS_FUNC,  
    JS_C_DOM_OBJECT,      
    JS_C_DOM_SINK,        

    JS_C_COMMENT
} js_class_t;

typedef enum {
    JS_S_START = 0,

    JS_S_SAW_TAG_OPEN,
    JS_S_SAW_HTML_TAG,
    JS_S_SAW_DANGEROUS_TAG,

    JS_S_SAW_EVENT_HANDLER,
    JS_S_SAW_ATTR_EQUALS,

    JS_S_SAW_JS_SCHEME,
    JS_S_SAW_DATA_SCHEME,

    JS_S_SAW_DANGEROUS_FUNC,

    JS_S_SAW_DOM_OBJECT,
    JS_S_SAW_DOT,
    JS_S_SAW_DOM_SINK,

    JS_S_ACCEPT
} js_state_t;

int check_js(lexer_t *lx);

#endif