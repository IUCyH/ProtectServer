#include <stdio.h>
#include <stdlib.h>
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

static char* GetEncryptKey()
{
	const int keyLength = 257;
	FILE* fp;
	char* key = (char*)malloc(sizeof(char) * keyLength);

	fp = fopen("/home/ubuntu/ProtectServer/TokenEncryptKey.txt", "r");

	if(fp == NULL)
	{
		fprintf(stderr, "Fail to open file");
		return NULL;
	}

	fgets(key, keyLength, fp);
	
	fclose(fp);
	return key;
}

int Authenticate(const char* token)
{
	jwt_t* jwt = NULL;
	char* encryptKey = GetEncryptKey();

	if(encryptKey == NULL)
	{
		fprintf(stderr, "EncryptKey is NULL");
		return ENCRYPT_KEY_NOT_FOUND;
	}

	int decodeResult = jwt_decode(&jwt, token, (const unsigned char*)encryptKey, strlen(encryptKey));

	free(encryptKey);

	if(decodeResult)
	{
		fprintf(stderr, "Can't decode a token");
		return DECODE_ERROR;
	}

	if(!ValidateExp(jwt))
	{
		return EXP_ERROR;
	}

	return SUCCESS;	
}
