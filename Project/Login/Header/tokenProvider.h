#ifndef TOKEN_PROVIDER_H

# define TOKEN_PROVIDER_H

#include <stdio.h>

char* MakeAccessToken(const char* uid);
char* MakeRefreshToken(const char* uid);

#endif
