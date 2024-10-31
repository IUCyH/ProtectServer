#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <cJSON.h>
#include <jwt.h>
#include "googleJWTInfoGenerator.h"

#define GOOGLE_OAUTH2_CERTS_URL "https://www.googleapis.com/oauth2/v3/certs"

size_t WriteData(void* ptr, size_t size, size_t nmemb, char* data)
{
	int dataSize = size * nmemb;

	strncat(data, ptr, dataSize);
	return dataSize;
}

char* GetGooglePublicKey()
{
	CURL* curl = curl_easy_init();

	if(curl == NULL)
	{
		fprintf(stderr, "Can't init curl objcet\n");
		return NULL;
	}

	char response[4096] = { 0, };
	char* result = (char*)malloc(sizeof(char) * 4096);

	curl_easy_setopt(curl, CURLOPT_URL, GOOGLE_OAUTH2_CERTS_URL);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteData);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, response);

	if(curl_easy_perform(curl) != CURLE_OK)
	{
		curl_easy_cleanup(curl);
		return NULL;
	}

	curl_easy_cleanup(curl);

	cJSON* parsedJson = cJSON_Parse(response);
    cJSON* keys = cJSON_GetObjectItem(parsedJson, "keys");
    cJSON* firstKey = cJSON_GetArrayItem(keys, 0);
    cJSON* n = cJSON_GetObjectItem(firstKey, "n");
    cJSON* e = cJSON_GetObjectItem(firstKey, "e");

	snprintf(result, 4096, "{\"kty\":\"RSA\",\"n\":\"%s\",\"e\":\"%s\"}", cJSON_GetStringValue(n), cJSON_GetStringValue(e));

	cJSON_Delete(parsedJson);
	return result;
}

GoogleUserInfo* GetInformation(const char* token)
{
	jwt_t* jwt = NULL;
	char* publicKey = GetGooglePublicKey();

	if(publicKey == NULL)
	{
		fprintf(stderr, "The Public Key is not vaild.\n");
		return NULL;
	}

	int decodeResult = jwt_decode(&jwt, token, (const unsigned char*)publicKey, strlen(publicKey));
	if(decodeResult)
	{
		fprintf(stderr, "Can't decode jwt token\n");

		free(publicKey);
		return NULL;
	}

	const char* sub = jwt_get_grant(jwt, "sub");
	GoogleUserInfo* userInfo = (GoogleUserInfo*)malloc(sizeof(GoogleUserInfo));

	if(sub == NULL)
	{
		fprintf(stderr, "Required claims not found.\n");
		
		jwt_free(jwt);
		free(publicKey);
		return NULL;
	}

	userInfo->uid = sub;

	jwt_free(jwt);
	free(publicKey);
	return userInfo;
}
