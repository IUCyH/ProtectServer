#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <jwt.h>
#include "queue.h"
#include "memoryPool.h"
#include "tokenAnalyzer.h"

jwt_t* DecodeToken(const char* token)
{
	char* encryptKey = getenv("JWT_SECRET_KEY");

	if(encryptKey == NULL)
	{
		return NULL;
	}

	jwt_t* jwt = NULL;
	int decodeFail = jwt_decode(&jwt, token, (const unsigned char*)encryptKey, strlen(encryptKey));

	if(decodeFail)
	{
		fprintf(stderr, "Fail to decode token");
		return NULL;
	}

	return jwt;
}

char* GetClaim(jwt_t* token, Pool* pool, const char* name)
{
	char* grant = (char*)jwt_get_grant(token, name);
	char* result = Get(pool, (sizeof(char) * strlen(grant) + 1));

	strcpy(result, grant);

	if(result == NULL)
	{
		fprintf(stderr, "Can't get claim from a token");
		return NULL;
	}

	return result;
}
