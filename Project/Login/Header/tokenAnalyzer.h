#ifndef TOKEN_ANALYZER_H

# define TOKEN_ANALYZER_H

#include <stdio.h>
#include <jwt.h>
#include "memoryPool.h"

jwt_t* DecodeToken(const char* token);
char* GetClaim(jwt_t* jwt, Pool* pool, const char* name);

#endif
