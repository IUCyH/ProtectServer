#include <stdio.h>
#include <string.h>
#include <time.h>
#include <jwt.h>
#include "tokenProvider.h"

char* MakeAccessToken(char* email, char* uid, char* encryptKey)
{
	jwt_t* jwt = NULL;
	time_t now = time(NULL);

	jwt_new(&jwt);

	jwt_add_grant(jwt, "email", email);
	jwt_add_grant(jwt, "sub", uid);
	jwt_add_grant(jwt, "iss", "protectmeios.xyz");
	
	jwt_add_grant_int(jwt, "iat", now);
	jwt_add_grant_int(jwt, "exp", now + 1800);

	jwt_set_alg(jwt, JWT_ALG_HS256, (unsigned char*)encryptKey, strlen(encryptKey));
	
	char* accessToken = jwt_encode_str(jwt);

	// TODO: Refresh 토큰 생성 및 관련 로직

	return accessToken;
}
