#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
#include "tokenAnalyzer.h"
#include "authenticator.h"

static int ValidateExp(jwt_t* decodedToken)
{
	int exp = jwt_get_grant_int(decodedToken, "exp");
	time_t now = time(NULL);

	if(exp < now)
	{
		return 0;
	}

	return 1;
}

AuthResult Authenticate(const char* token)
{
	jwt_t* jwt = DecodeToken(token);
	AuthResult authResult;

	authResult.code = 0;
	authResult.jwt = NULL;

	if(jwt == NULL)
	{
		authResult.code = DECODE_ERROR;
	}
	else if(!ValidateExp(jwt))
	{
		fprintf(stderr, "Token expired");
		authResult.code = EXP_ERROR;
	}
	else
	{
		authResult.code = SUCCESS;
		authResult.jwt = jwt;
	}

	return authResult;
}
