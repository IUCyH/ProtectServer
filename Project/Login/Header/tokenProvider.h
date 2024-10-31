#ifndef TOKEN_PROVIDER_H

# define TOKEN_PROVIDER_H

#include <stdio.h>

char* MakeAccessToken(const char* uid, const char* encryptKey);
char* MakeRefreshToken(const char* uid, const char* encryptKey);

#endif
