#include <stdio.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
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

int Authenticate(const char* token, const char* encryptKey)
{
	jwt_t* jwt = NULL;
	int decodeResult = jwt_decode(&jwt, token, (const unsigned char*)encryptKey, strlen(encryptKey));

	if(decodeResult)
	{
		fprintf(stderr, "Can't decode a token");
		return DECODE_ERROR;
	}

	if(!ValidateExp(jwt))
	{
		return EXP_ERROR;
		// TODO: Main에서 Refresh 토큰 사용해 새 토큰 발급 로직
	}

	return SUCCESS;	
}
