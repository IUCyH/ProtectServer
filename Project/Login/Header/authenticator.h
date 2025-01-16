#ifndef AUTHENTICATOR_H

# define AUTHENTICATOR

#define DECODE_ERROR -1
#define EXP_ERROR 0
#define SUCCESS 1

#include <stdio.h>
#include <jwt.h>

typedef struct AuthResult
{
	int code;
	jwt_t* jwt;
}AuthResult;

AuthResult Authenticate(const char* token);

#endif
