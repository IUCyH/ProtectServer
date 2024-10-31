#ifndef AUTHENTICATOR_H

# define AUTHENTICATOR

#define DECODE_ERROR -1
#define EXP_ERROR 0
#define SUCCESS 1

#include <stdio.h>

int Authenticate(const char* token, const char* encryptKey);

#endif
