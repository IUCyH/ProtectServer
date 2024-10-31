#ifndef AUTHENTICATOR_H

# define AUTHENTICATOR

#define ENCRYPT_KEY_NOT_FOUND -2
#define DECODE_ERROR -1
#define EXP_ERROR 0
#define SUCCESS 1

#include <stdio.h>

int Authenticate(const char* token);

#endif
