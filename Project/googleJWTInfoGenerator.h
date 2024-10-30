#ifndef GOOGLE_JWT_INFO_GENERATOR_H

# define GOOGLE_JWT_INFO_GENERATOR_H

#include <stdio.h>

typedef struct GoogleUserInfo
{
	const char* uid;
	const char* email;
}GoogleUserInfo;

GoogleUserInfo* GetInformation(const char* token);

#endif
