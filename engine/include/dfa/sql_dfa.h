#ifndef SQL_DFA_H
#define SQL_DFA_H

#include <stdint.h>
#include "../rules/lexer.h"
#include <string.h>


typedef enum {
    SQL_C_OTHER = 0,

    SQL_C_QUOTE,
    SQL_C_WORD,
    SQL_C_NUMBER,
    SQL_C_NULL,

    SQL_C_BOOL_OP,        
    SQL_C_COMPARE_OP,     

    SQL_C_UNION,
    SQL_C_SELECT,
    SQL_C_FROM,
    SQL_C_WHERE,

    SQL_C_COMMENT,        
    SQL_C_SEMICOLON,      
    SQL_C_COMMA,          
    SQL_C_STAR,           

    SQL_C_PAREN_OPEN,     
    SQL_C_PAREN_CLOSE,    

    SQL_C_DANGEROUS_STMT, 
    SQL_C_TIME_FUNC,      
    SQL_C_ERROR_FUNC,     
    SQL_C_METADATA        
} sql_class_t;

typedef enum {
    SQL_S_START = 0,
    SQL_S_SAW_BOUNDARY,
    SQL_S_SAW_BOOL,
    SQL_S_SAW_LHS,
    SQL_S_SAW_COMPARE,
    SQL_S_SAW_UNION,
    SQL_S_SAW_SEMICOLON,
    SQL_S_SAW_SELECT,
    SQL_S_SAW_FROM,
    SQL_S_ACCEPT
} sql_state_t;

int check_sqli(lexer_t *lx);


#endif