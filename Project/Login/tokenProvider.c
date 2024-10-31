#include <stdio.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
#include "tokenProvider.h"

#define ISS "IUCyH"

char* MakeAccessToken(const char* uid, const char* encryptKey)
{
	jwt_t* jwt = NULL;
	time_t now = time(NULL);
	int thirtyMinutes = 1800;

	jwt_new(&jwt);

	jwt_add_grant(jwt, "sub", uid);
	jwt_add_grant(jwt, "iss", ISS);
	
	jwt_add_grant_int(jwt, "iat", now);
	jwt_add_grant_int(jwt, "exp", now + thirtyMinutes);

	jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char*)encryptKey, strlen(encryptKey));
	
	char* accessToken = jwt_encode_str(jwt);
	return accessToken;
}

char* MakeRefreshToken(const char* uid, const char* encryptKey)
{
	jwt_t* jwt = NULL;
	time_t now = time(NULL);
	int oneMonth = 2629800;

	jwt_new(&jwt);

	jwt_add_grant(jwt, "sub", uid);
	jwt_add_grant(jwt, "iss", ISS);
	
	jwt_add_grant_int(jwt, "iat", now);
	jwt_add_grant_int(jwt, "exp", now + oneMonth);

	jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char*)encryptKey, strlen(encryptKey));
	
	char* refreshToken = jwt_encode_str(jwt);
	return refreshToken;
}
