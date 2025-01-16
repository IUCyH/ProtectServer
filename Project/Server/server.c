#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include "mongoose.h"
#include <mariadb/mysql.h>
#include <cJSON.h>
#include <argon2.h>
#include "queue.h"
#include "memoryPool.h"
#include "dataHandler.h"
#include "tokenProvider.h"
#include "tokenAnalyzer.h"
#include "authenticator.h"
#include "server.h"

#define HASH_LENGTH 32
#define DECODE_LENGTH 256
#define JSON_TYPE_HEADER "Content-Type: application/json\r\n"

Pool* pool;

static int IsNull(int type)
{
	return type == 4 ? 1 : 0;
}

static int IsString(int type)
{
	return type == 16 ? 1 : 0;
}

static int IsNumber(int type)
{
	return type == 8 ? 1 : 0;
}

static void WriteLog(char* message)
{
	FILE* fp = fopen("/var/log/server.log", "a");

	if(fp == NULL)
	{
		return;
	}

	fputs(message, fp);
	fclose(fp);
}

static char* GetTokenFromHeader(char* header)
{
	char* nextPtr = NULL;
	char* trash = strtok_r(header, " ", &nextPtr);

	if(trash == NULL)
	{
		return NULL;
	}

	char* result = strtok_r(NULL, " ", &nextPtr);
	return result;
}

static jwt_t* GetDecodedToken(const char* token)
{
	AuthResult result = Authenticate(token);

	switch(result.code)
	{
		case DECODE_ERROR:
		case EXP_ERROR:
			return NULL;
		case SUCCESS:
			return result.jwt;
	}

	return NULL;
}

static char* GetStringFromMG(struct mg_str mg)
{	
	char* str = Get(pool, (sizeof(char) * (mg.len + 1)));
	strncpy(str, mg.buf, mg.len);
	str[mg.len] = '\0';

	return str;
}

static char* GetHashValue(char* salt, char* value)
{
	char* hashedResult = Get(pool, (sizeof(char) * DECODE_LENGTH));
	int encodeSuccess = argon2id_hash_encoded(3, 1 << 20, 8, value, strlen(value),
											  salt, strlen(salt), HASH_LENGTH, hashedResult, DECODE_LENGTH);
		
	if(encodeSuccess != ARGON2_OK)
	{
		return NULL;
	}
	else
	{
		return hashedResult;
	}
}

static int GetJSONKeysAndBindValues(cJSON* obj, char** keys, MYSQL_BIND* binds)
{
	cJSON* item = NULL;
	int index = 0;

	cJSON_ArrayForEach(item, obj)
	{
    	keys[index] = Get(pool, (sizeof(char) * 51));

    	strcpy(keys[index], item->string);
		
    	if(IsNull(item->type))
    	{
			enum enum_field_types type = GetBufferType("User", item->string);
			MakeBindNULL(&binds[index++], pool, type); 
    	}
    	else if(IsString(item->type))
    	{
        	if(!strcmp(item->string, "password"))
        	{
            	char* salt = getenv("SECRET_SALT");

            	if(salt == NULL)
            	{
					WriteLog("In GetJsonItems, line 143: Can't get a salt.\n");
					return 0;
            	}

            	char* hashedResult = GetHashValue(salt, item->valuestring);
            	if(hashedResult == NULL)
            	{
                	WriteLog("In GetJsonItems, line 149: Password not hashed.\n");	
                	return 0;
            	}
				
            	MakeBindString(&binds[index++], pool, hashedResult, sizeof(hashedResult));
        	}
        	else
        	{
				char* valueStr = Get(pool, (sizeof(char) * strlen(item->valuestring) + 1));
				strcpy(valueStr, item->valuestring);
				
            	MakeBindString(&binds[index++], pool, valueStr, sizeof(valueStr));
        	}
    	}
    	else if(IsNumber(item->type))
    	{
			int* valueInt = Get(pool, sizeof(int));
			*valueInt = (int)item->valuedouble;

			MakeBindInt(&binds[index++], pool, valueInt);
    	}
	}

	return 1;
}

static jwt_t* FullAuthorization(struct mg_connection* c, struct mg_http_message* hm)
{
	struct mg_str* headerValue = mg_http_get_header(hm, "Authorization");
	if(headerValue == NULL || headerValue->buf == NULL)
	{
		WriteLog("In FullAuthorization, line 145: Can't find required header.\n");

		mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required header not found\"}");
		return NULL;
	}

	char* header = GetStringFromMG(*headerValue);
	char* token = GetTokenFromHeader(header);
	if(token == NULL)
	{
		WriteLog("In FullAuthorization, line 155: Can't get a token from header.\n");

		Set(pool, (void*)header);
		mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Can't find token\"}");
		return NULL;
	}

	jwt_t* jwt = GetDecodedToken(token);
	
	Set(pool, (void*)header);
	if(jwt == NULL)
	{
		WriteLog("In FullAuthorization, line 165: Token isn't valid.\n");
			
		mg_http_reply(c, 401, JSON_TYPE_HEADER, "{\"message\": \"Unauthorized\"}");
		return NULL;
	}

	return jwt;
}

static void HandleDelete(struct mg_connection* c, struct mg_http_message* hm, const char* url)
{
	if(!strcmp(url, "/user"))
	{
		jwt_t* jwt = FullAuthorization(c, hm);

		if(jwt == NULL)
		{
			return;
		}

		char* idString = GetClaim(jwt, pool, "sub");

		jwt_free(jwt);
		if(idString == NULL)
		{
			WriteLog("In HandleDelete, line 219: Can't get a id from token.\n");

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't get uid from a token\"}");
			return;
		}

		MYSQL_BIND bind[1];
		MakeBindString(&bind[0], pool, idString, sizeof(idString));

		MYSQL_STMT* stmt = MakeDeleteSTMT("User", "email = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandleDelete, line 234: STMT is NULL.\n");

			ClearBinds(bind, pool, 1);	

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(stmt, bind);
		
		int success = ExecuteQuery(stmt);

		ClearBinds(bind, pool, 1);

		if(!success)
		{
			WriteLog("In HandleDelete, line 252: Query faild.\n");

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		mg_http_reply(c, 200, JSON_TYPE_HEADER, "{\"message\": \"Delete success\"}");
		return;
	}

	mg_http_reply(c, 501, JSON_TYPE_HEADER, "{\"message\": \"Invaild URL\"}");
}

static void HandlePut(struct mg_connection* c, struct mg_http_message* hm, const char* url)
{
	if(!strcmp(url, "/user"))
	{
		jwt_t* jwt = FullAuthorization(c, hm);

		if(jwt == NULL)
		{
			return;
		}

		char* idString = GetClaim(jwt, pool, "sub");
		if(idString == NULL)
		{
			WriteLog("In HandlePut, line 175: Can't get id from url query string.\n");

			jwt_free(jwt);
			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't get uid from a token\"}");
			return;
		}

		if(hm->body.buf == NULL)
		{
			WriteLog("In HandlePut, line 159: Can't get a body.\n");

			jwt_free(jwt);
			Set(pool, (void*)idString);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required body not found\"}");
			return;
		}

		char* body = GetStringFromMG(hm->body);
		cJSON* obj = cJSON_Parse(body);

		Set(pool, (void*)body);
		if(obj == NULL)
		{
			WriteLog("In HandlePut, line 187: Can't parse the body into json.\n");

			jwt_free(jwt);
			Set(pool, (void*)idString);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Can't get a value from a body\"}");
			return;
		}

		int valueCount = cJSON_GetArraySize(obj);
		char** keyArr = Get(pool, (sizeof(char*) * valueCount));
		MYSQL_BIND binds[valueCount + 1];

		int readJsonSuccess = GetJSONKeysAndBindValues(obj, keyArr, binds);

		cJSON_Delete(obj);
		if(!readJsonSuccess)
		{
			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"JSON read faild\"}");

			jwt_free(jwt);
			Set(pool, (void*)idString);

			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);
		
			ClearBinds(binds, pool, valueCount);
			return;
		}

		char setValues[512] = "";
		for(int i = 0; i < valueCount; i++)
		{
			strcat(setValues, keyArr[i]);
			strcat(setValues, " = ?");

			if(i != valueCount - 1)
			{
				strcat(setValues, ", ");
			}
		}
		MakeBindString(&binds[valueCount], pool, idString, sizeof(idString));

		MYSQL_STMT* stmt = MakeUpdateSTMT("User", setValues, "email = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandlePut, line 357: STMT is NULL.\n");

			jwt_free(jwt);	

			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount + 1);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(stmt, binds);
		
		int success = ExecuteQuery(stmt);

		jwt_free(jwt);

		for(int i = 0; i < valueCount; i++)
		{
			Set(pool, (void*)keyArr[i]);
		}
		Set(pool, (void*)keyArr);	
		
		ClearBinds(binds, pool, valueCount + 1);
		EndQuery(stmt);

		if(!success)
		{
			WriteLog("In HandlePut, line 273: Query faild.\n");

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		mg_http_reply(c, 200, JSON_TYPE_HEADER, "{\"message\": \"Update Success\"}");	
		return;
	}

	mg_http_reply(c, 501, JSON_TYPE_HEADER, "{\"message\": \"Invalid URL\"}");
}

static void HandlePost(struct mg_connection* c, struct mg_http_message* hm, const char* url)
{
	if(!strcmp(url, "/user/signin/auto"))
	{	
		jwt_t* jwt = FullAuthorization(c, hm);

		if(jwt == NULL)
		{
			return;
		}

		char* idString = GetClaim(jwt, pool, "sub");
		if(idString == NULL)
		{
			WriteLog("In HandlePost, line 328: Can't get id from url query string.\n");

			jwt_free(jwt);
			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't get uid from a token\"}");
			return;
		}
		
		MYSQL_BIND bind[1];
		MakeBindString(&bind[0], pool, idString, sizeof(idString));
		MYSQL_STMT* stmt = MakeSelectSTMT("User", "email = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandlePost, line 426: STMT is NULL.\n");

			jwt_free(jwt);	
			ClearBinds(bind, pool, 1);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(stmt, bind);

		int success = ExecuteQuery(stmt);
		if(!success)
		{
			WriteLog("In HandlePost, line 342: Query faild.\n");

			jwt_free(jwt);
			ClearBinds(bind, pool, 1);
			EndQuery(stmt);

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't find requested data\"}");
			return;
		}

		MYSQL_RES* metadata = GetMetadata(stmt);
		MYSQL_FIELD* fields = GetFields(metadata);
		unsigned long columnCount = GetColumnCount(metadata);

		MYSQL_BIND resultBinds[columnCount];
		for(int i = 0; i < columnCount; i++)
		{	
			if(fields[i].type == MYSQL_TYPE_TIMESTAMP)
			{
				char* buffer = Get(pool, (sizeof(char) * 21));
				MakeBindString(&resultBinds[i], pool, buffer, 21);
			}
			else if(fields[i].type == MYSQL_TYPE_LONG)
			{
				int* buffer = Get(pool, sizeof(int));
				MakeBindInt(&resultBinds[i], pool, buffer);
			}
			else
			{
				char* buffer = Get(pool, (sizeof(char) * 512));
				MakeBindString(&resultBinds[i], pool, buffer, 512);
			}
		}

		BindSTMTResult(stmt, resultBinds);	
	
		int fetchSuccess = FetchQueryResult(stmt);
		if(!fetchSuccess)
		{
			WriteLog("In HandlePost, line 417: Fetch faild.\n");	

			jwt_free(jwt);
			ClearMetadata(metadata);
			ClearBinds(bind, pool, 1);
			ClearBinds(resultBinds, pool, columnCount);
			EndQuery(stmt);

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Fetch faild\"}");
			return;
		}

		cJSON* obj = cJSON_CreateObject();
		char* json = Get(pool, (sizeof(char) * 256));

		for(int i = 0; i < columnCount; i++)
		{
			char* key = fields[i].name;

			if(!strcmp(key, "password") || !strcmp(key, "create_at"))
			{
				continue;
			}

			if(resultBinds[i].buffer_type == MYSQL_TYPE_LONG)
			{
				cJSON_AddNumberToObject(obj, key, *((int*)resultBinds[i].buffer));
			}
			else if(resultBinds[i].buffer_type == MYSQL_TYPE_STRING)
			{
				cJSON_AddStringToObject(obj, key, (char*)resultBinds[i].buffer);
			}
		}	

		strcpy(json, cJSON_PrintUnformatted(obj));

		mg_http_reply(c, 200, JSON_TYPE_HEADER, json);	

		Set(pool, (void*)json);
		jwt_free(jwt);
		ClearMetadata(metadata);
		ClearBinds(bind, pool, 1);
		ClearBinds(resultBinds, pool, columnCount);
		EndQuery(stmt);
		cJSON_Delete(obj);
		return;
	}

	if(!strcmp(url, "/user/signin"))
	{
		if(hm->body.buf == NULL)
		{
			WriteLog("In HandlePost, line 387: Body is NULL.\n");

			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required body not found\"}");
			return;
		}

		char* body = GetStringFromMG(hm->body);
		cJSON* obj = cJSON_Parse(body);

		Set(pool, (void*)body);
		if(obj == NULL)
		{
			WriteLog("In HandlePost, line 399: Can't parse the body into json.\n");
			
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Can't get a value from a body\"}");
			return;
		}
		
		cJSON* id = cJSON_GetObjectItem(obj, "id");
		cJSON* password = cJSON_GetObjectItem(obj, "password");
	
		if(id == NULL || password == NULL || id->valuestring == NULL || password->valuestring == NULL)
		{
			WriteLog("In HandlePost, line 410: Can't get id or password from body.\n");
	
			cJSON_Delete(obj);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"ID or Password not found from a body\"}");
			return;
		}

		char* salt = getenv("SECRET_SALT");	
		if(salt == NULL)
		{
			WriteLog("In HandlePost, line 419: Can't get a salt.\n");

			cJSON_Delete(obj);
			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		char* hashedResult = GetHashValue(salt, password->valuestring);	

		if(hashedResult == NULL)
		{
			WriteLog("In HandlePost, line 429: Encode fail.\n");

			cJSON_Delete(obj);
			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Fail to encode\"}");
			return;
		}
		
		MYSQL_BIND binds[2];
		
		MakeBindString(&binds[0], pool, id->valuestring, sizeof(id->valuestring));
		MakeBindString(&binds[1], pool, hashedResult, sizeof(hashedResult));

		MYSQL_STMT* stmt = MakeSelectSTMT("User", "email = ? AND password = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandlePost, line 609: STMT is NULL.\n");

			cJSON_Delete(obj);

			binds[0].buffer = NULL;

			ClearBinds(binds, pool, 2);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(stmt, binds);
		
		int querySuccess = ExecuteQuery(stmt);
		if(!querySuccess)
		{
			WriteLog("In HandlePost, line 563: Query faild.\n");

			cJSON_Delete(obj);
			
			binds[0].buffer = NULL;

			ClearBinds(binds, pool, 2);
			EndQuery(stmt);

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		MYSQL_RES* metadata = GetMetadata(stmt);
		MYSQL_FIELD* fields = GetFields(metadata);
		unsigned long columnCount = GetColumnCount(metadata);

		MYSQL_BIND resultBinds[columnCount];
		for(int i = 0; i < columnCount; i++)
		{	
			if(fields[i].type == MYSQL_TYPE_TIMESTAMP)
			{
				char* buffer = Get(pool, (sizeof(char) * 21));
				MakeBindString(&resultBinds[i], pool, buffer, 21);
			}
			else if(fields[i].type == MYSQL_TYPE_LONG)
			{
				int* buffer = Get(pool, sizeof(int));
				MakeBindInt(&resultBinds[i], pool, buffer);
			}
			else
			{
				char* buffer = Get(pool, (sizeof(char) * 512));
				MakeBindString(&resultBinds[i], pool, buffer, 512);
			}
		}

		BindSTMTResult(stmt, resultBinds);

		int fetchSuccess = FetchQueryResult(stmt);
		if(!fetchSuccess)
		{
			WriteLog("In HandlePost, line 580: Fetch faild.\n");

			cJSON_Delete(obj);
			
			binds[0].buffer = NULL;

			ClearMetadata(metadata);
			ClearBinds(binds, pool, 2);
			ClearBinds(resultBinds, pool, columnCount);
			EndQuery(stmt);

			mg_http_reply(c, 401, JSON_TYPE_HEADER, "{\"message\": \"Fetch faild\"}");
			return;
		}	

		char* accessToken = MakeAccessToken(id->valuestring);
		char* refreshToken = MakeRefreshToken(id->valuestring);
	
		if(accessToken == NULL || refreshToken == NULL)
		{	
			WriteLog("In HandlePost, line 485: Can't make a token.\n");

			if(accessToken != NULL)
			{
				free(accessToken);
			}

			if(refreshToken != NULL)
			{
				free(refreshToken);
			}

			cJSON_Delete(obj);
			binds[0].buffer = NULL;
	
			ClearMetadata(metadata);
			ClearBinds(binds, pool, 2);
			ClearBinds(resultBinds, pool, columnCount);
			EndQuery(stmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Can't make a token\"}");
			return;
		}

		cJSON* tokenObj = cJSON_CreateObject();
		cJSON* userObj = cJSON_CreateObject();
		cJSON* resultObj = cJSON_CreateObject();
		for(int i = 0; i < columnCount; i++)
		{
			char* key = fields[i].name;

			if(!strcmp(key, "password") || !strcmp(key, "create_at"))
			{
				continue;
			}

			if(resultBinds[i].buffer_type == MYSQL_TYPE_LONG)
			{
				cJSON_AddNumberToObject(userObj, key, *((int*)resultBinds[i].buffer));
			}
			else if(resultBinds[i].buffer_type == MYSQL_TYPE_STRING)
			{
				cJSON_AddStringToObject(userObj, key, (char*)resultBinds[i].buffer);
			}
		}

		cJSON_AddStringToObject(tokenObj, "access_token", accessToken);
		cJSON_AddStringToObject(tokenObj, "refresh_token", refreshToken);	

		cJSON_AddItemToObject(resultObj, "token", tokenObj);
		cJSON_AddItemToObject(resultObj, "user", userObj);

		char* json = Get(pool, (512 * sizeof(char)));
		strcpy(json, cJSON_PrintUnformatted(resultObj));

		mg_http_reply(c, 200, JSON_TYPE_HEADER, json);

		cJSON_Delete(obj);
		Set(pool, (void*)json);
		binds[0].buffer = NULL;

		ClearMetadata(metadata);
		ClearBinds(binds, pool, 2);
		ClearBinds(resultBinds, pool, columnCount);
		EndQuery(stmt);

		free(accessToken);
		free(refreshToken);

		cJSON_Delete(resultObj);
		return;
	}
	
	if(!strcmp(url, "/user/signup"))
	{
		if(hm->body.buf == NULL)
		{
			WriteLog("In HandlePost, line 519: Body is NULL.\n");

			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required body not found\"}");
			return;
		}

		char* body = GetStringFromMG(hm->body);
		cJSON* obj = cJSON_Parse(body);

		Set(pool, (void*)body);
		if(obj == NULL)
		{
			WriteLog("In HandlePost, line 531: Can't parse the body.\n");

			mg_http_reply(c, 304, JSON_TYPE_HEADER, "{\"message\": \"Can't parse the body. check it\"}");
			return;
		}

		int valueCount = cJSON_GetArraySize(obj);
		char** keyArr = Get(pool, (sizeof(char*) * valueCount)); 
		MYSQL_BIND binds[valueCount];

		int readJsonSuccess = GetJSONKeysAndBindValues(obj, keyArr, binds);
		if(!readJsonSuccess)
		{
			WriteLog("In HandlePost, line 545: Can't read json.\n");

			cJSON_Delete(obj);

			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			
			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Server error\"}");
			return;
		}

		char keys[512] = "";
		char values[512] = "";
		for(int i = 0; i < valueCount; i++)
		{
			strcat(keys, keyArr[i]);
			strcat(values, "?");
			
			if(i != valueCount - 1)
			{
				strcat(keys, ", ");
				strcat(values, ", ");
			}
		}

		MYSQL_STMT* stmt = MakeInsertSTMT("User", keys, values);

		if(stmt == NULL)
		{
			WriteLog("In HandlePost, line 776: STMT is NULL.\n");

			cJSON_Delete(obj);
			
			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(stmt, binds);
		
		int success = ExecuteQuery(stmt);

		cJSON_Delete(obj);
		
		for(int i = 0; i < valueCount; i++)
		{
			Set(pool, (void*)keyArr[i]);
		}
		Set(pool, (void*)keyArr);

		ClearBinds(binds, pool, valueCount);
		EndQuery(stmt);

		if(!success)
		{
			WriteLog("In HandlePost, line 591: Query Faild.\n");	

			mg_http_reply(c, 304, JSON_TYPE_HEADER, "{\"message\": \"Query Faild\"}");
			return;
		}

		mg_http_reply(c, 200, JSON_TYPE_HEADER, "{\"message\": \"Create success\"}");
		return;
	}

	if(!strcmp(url, "/post"))
	{
		jwt_t* jwt = FullAuthorization(c, hm);

		if(jwt == NULL)
		{
			return;
		}

		char* idString = GetClaim(jwt, pool, "sub");

		jwt_free(jwt);
		if(idString == NULL)
		{
			WriteLog("In HandlePost, line 815: Can't get id from a token.\n");

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't get uid from a token.\"}");
			return;
		}

		if(hm->body.buf == NULL)
		{
			WriteLog("In HandlePost, line 824: Can't get a body.\n");

			Set(pool, (void*)idString);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required body not found.\"}");
			return;
		}

		char* body = GetStringFromMG(hm->body);
		cJSON* obj = cJSON_Parse(body);

		Set(pool, (void*)body);
		if(obj == NULL)
		{
			WriteLog("In HandlePost, line 836: Can't parse the body into json.\n");

			Set(pool, (void*)idString);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Can't get a value from a body\"}");
			return;
		}

		int valueCount = cJSON_GetArraySize(obj);
		char** keyArr = Get(pool, (sizeof(char*) * valueCount));
		MYSQL_BIND binds[valueCount + 1];

		int readJsonSuccess = GetJSONKeysAndBindValues(obj, keyArr, binds);

		cJSON_Delete(obj);
		if(!readJsonSuccess)
		{
			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"JSON read faild\"}");

			Set(pool, (void*)idString);

			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			return;
		}

		char* category = Get(pool, (sizeof(char) * 128));
		for(int i = 0; i < valueCount; i++)
		{
			if(!strcmp(keyArr[i], "category_name"))
			{
				strcpy(category, binds[i].buffer);
				break;
			}
		}

		StartTransaction();

		MYSQL_BIND categoryBind[1];

		MakeBindString(&categoryBind[0], pool, category, sizeof(category));
		MYSQL_STMT* categoryStmt = MakeSelectWithColumnsSTMT("id", "Category", "name = ?");
		if(categoryStmt == NULL)
		{
			WriteLog("In HandlePost, line 883: STMT is NULL.\n");

			Set(pool, (void*)idString);

			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			ClearBinds(categoryBind, pool, 1);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		BindSTMTParam(categoryStmt, categoryBind);
		
		int querySuccess = ExecuteQuery(categoryStmt);
		if(!querySuccess)
		{
			WriteLog("In HandlePost, line 900: Query faild.\n");

			Set(pool, (void*)idString);
			
			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			ClearBinds(categoryBind, pool, 1);
			StopTransaction(categoryStmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		MYSQL_BIND categoryResultBind[1];
		int* idBuffer = Get(pool, sizeof(int));

		MakeBindInt(&categoryResultBind[0], pool, idBuffer);
		BindSTMTResult(categoryStmt, categoryResultBind);

		int fetchSuccess = FetchQueryResult(categoryStmt);
		if(!fetchSuccess)
		{
			WriteLog("In HandlePost, line 922: Fetch faild.\n");

			Set(pool, (void*)idString);
			
			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			ClearBinds(categoryBind, pool, 1);
			ClearBinds(categoryResultBind, pool, 1);
			StopTransaction(categoryStmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Fetch faild\"}");
			return;
		}

		ClearBinds(categoryBind, pool, 1);
		EndQuery(categoryStmt);
		
		char keys[256] = "";
		char values[512] = "";
	
		for(int i = 0; i < valueCount; i++)
		{
			if(!strcmp(keyArr[i], "category_name"))
			{
				strcat(keys, "category_id");

				free(binds[i].buffer);
				free(binds[i].length);
				free(binds[i].is_null);

				MakeBindInt(&binds[i], pool, idBuffer);
			}
			else
			{
				strcat(keys, keyArr[i]);
			}

			strcat(values, "?");

			strcat(keys, ", ");
			strcat(values, ", ");
		}

		strcat(keys, "owner_id");
		strcat(values, "?");

		MYSQL_STMT* stmt = MakeInsertSTMT("Post", keys, values);
		if(stmt == NULL)
		{
			WriteLog("In HandlePost, line 953: STMT is NULL.\n");

			Set(pool, (void*)idString);
			
			for(int i = 0; i < valueCount; i++)
			{
				Set(pool, (void*)keyArr[i]);
			}
			Set(pool, (void*)keyArr);

			ClearBinds(binds, pool, valueCount);
			ClearBinds(categoryBind, pool, 1);
			ClearBinds(categoryResultBind, pool, 1);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Server error\"}");
			return;
		}

		MakeBindString(&binds[valueCount], pool, idString, sizeof(idString));
		BindSTMTParam(stmt, binds);

		querySuccess = ExecuteQuery(stmt);
	
		for(int i = 0; i < valueCount; i++)
		{
			Set(pool, (void*)keyArr[i]);
		}
		Set(pool, (void*)keyArr);
		
		ClearBinds(binds, pool, valueCount + 1);
		ClearBinds(categoryBind, pool, 1);

		if(!querySuccess)
		{
			WriteLog("In HandlePost, line 994: Query faild.\n");

			StopTransaction(stmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		EndQuery(stmt);
		EndTransaction();

		mg_http_reply(c, 200, JSON_TYPE_HEADER, "{\"message\": \"Post success\"}");
		return;
	}

	if(!strcmp(url, "/auth/refresh"))
	{
		jwt_t* jwt = FullAuthorization(c, hm);

		if(jwt == NULL)
		{
			return;
		}

		char* idString = GetClaim(jwt, pool, "sub");
		if(idString == NULL)
		{
			WriteLog("In HandlePost, line 745: Can't get id from url query string.\n");

			jwt_free(jwt);
			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't get uid from a token\"}");
			return;
		}

		char* accessToken = MakeAccessToken(idString);

		jwt_free(jwt);
		if(idString != NULL)
		{
			Set(pool, (void*)idString);
		}
		if(accessToken == NULL)
		{
			WriteLog("In HandlePost, line 664: Can't make a token.\n");

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Can't make a token\"}");
			return;
		}

		char* json = Get(pool, (sizeof(char) * 512));
		sprintf(json, "{\"access_token\": \"%s\"}", accessToken);

		mg_http_reply(c, 200, JSON_TYPE_HEADER, json);

		free(accessToken);
		Set(pool, (void*)json);
		return;
	}

	mg_http_reply(c, 501, JSON_TYPE_HEADER, "{\"message\": \"Invalid URL\"}");
}

static void HandleGet(struct mg_connection* c, struct mg_http_message* hm, const char* url)
{
	if(!strcmp(url, "/check-exists/email/data"))
	{
		if(hm->query.buf == NULL)
		{
			WriteLog("In HandleGet, line 689: Can't get query.\n");

			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required query not found\"}");
			return;
		}

		char* email = Get(pool, (sizeof(char) * 101));
		int success = mg_http_get_var(&hm->query, "email", email, 101);

		if(!success)
		{
			WriteLog("In HandleGet, line 700: Query exist, but can't get a value from a query.\n");

			Set(pool, (void*)email);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Email not found from a query\"}");
			return;
		}

		int* resultBuffer = Get(pool, sizeof(int));
		MYSQL_BIND bind[1];
		MYSQL_BIND resultBind[1];
		MYSQL_STMT* stmt = MakeExistSTMT("User", "email = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandleGet, line 899: STMT is NULL.\n");

			Set(pool, (void*)email);
			Set(pool, (void*)resultBuffer);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		MakeBindString(&bind[0], pool, email, sizeof(email));
		MakeBindInt(&resultBind[0], pool, resultBuffer);

		BindSTMT(stmt, bind, resultBind);

		int querySuccess = ExecuteQuery(stmt);
		if(!querySuccess)
		{
			WriteLog("In HandleGet, line 814: Query Faild.\n");

			ClearBinds(bind, pool, 1);
			ClearBinds(resultBind, pool, 1);
			EndQuery(stmt);

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		int fetchSuccess = FetchQueryResult(stmt);
		if(!fetchSuccess)
		{
			WriteLog("In HandleGet, line 826: Fetch faild.\n");

			ClearBinds(bind, pool, 1);
			ClearBinds(resultBind, pool, 1);
			EndQuery(stmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Fetch faild\"}");
			return;
		}

		int exist = *((int*)resultBind[0].buffer);
		char* json = Get(pool, (sizeof(char) * 51));
		sprintf(json, "{\"exist\": %s}", exist == 1 ? "true" : "false");

		mg_http_reply(c, 200, JSON_TYPE_HEADER, json);

		ClearBinds(bind, pool, 1);
		ClearBinds(resultBind, pool, 1);
		EndQuery(stmt);
		Set(pool, (void*)json);
		return;
	}

	if(!strcmp(url, "/check-exists/nickname/data"))
	{
		if(hm->query.buf == NULL)
		{
			WriteLog("In HandleGet, line 727: Can't get query.\n");

			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Required query not found\"}");
			return;
		}

		char* nickname = Get(pool, (sizeof(char) * 101));
		int success = mg_http_get_var(&hm->query, "nickname", nickname, 101);

		if(!success)
		{
			WriteLog("In HandleGet, line 738: Query exist, but can't get a value from a query.\n");

			Set(pool, nickname);
			mg_http_reply(c, 400, JSON_TYPE_HEADER, "{\"message\": \"Nickname not found from a query\"}");
			return;
		}

		int* resultBuffer = Get(pool, sizeof(int));
		MYSQL_BIND bind[1];
		MYSQL_BIND resultBind[1];
		MYSQL_STMT* stmt = MakeExistSTMT("User", "nickname = ?");

		if(stmt == NULL)
		{
			WriteLog("In HandleGet, line 980: STMT is NULL.\n");

			Set(pool, nickname);
			Set(pool, resultBuffer);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Error in server\"}");
			return;
		}

		MakeBindString(&bind[0], pool, nickname, sizeof(nickname));
		MakeBindInt(&resultBind[0], pool, resultBuffer);

		BindSTMT(stmt, bind, resultBind);

		int querySuccess = ExecuteQuery(stmt);
		if(!querySuccess)
		{
			WriteLog("In HandleGet, line 885: Query Faild.\n");

			ClearBinds(bind, pool, 1);
			ClearBinds(resultBind, pool, 1);
			EndQuery(stmt);

			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Query faild\"}");
			return;
		}

		int fetchSuccess = FetchQueryResult(stmt);
		if(!fetchSuccess)
		{
			WriteLog("In HandleGet, line 898: Fetch faild.\n");

			ClearBinds(bind, pool, 1);
			ClearBinds(resultBind, pool, 1);
			EndQuery(stmt);

			mg_http_reply(c, 500, JSON_TYPE_HEADER, "{\"message\": \"Fetch faild\"}");
			return;
		}

		int exist = *((int*)resultBind[0].buffer);
		char* json = Get(pool, (sizeof(char) * 51));
		sprintf(json, "{\"exist\": %s}", exist == 1 ? "true" : "false");

		mg_http_reply(c, 200, JSON_TYPE_HEADER, json);

		ClearBinds(bind, pool, 1);
		ClearBinds(resultBind, pool, 1);
		EndQuery(stmt);
		Set(pool, json);
		return;
	}

	if(!strcmp(url, "/image/test"))
	{
		char* path = "/home/ubuntu/HealthAssistant-backend/Images/test.png";
		FILE* fp = fopen(path, "rb");

		if(fp == NULL)
		{
			mg_http_reply(c, 404, JSON_TYPE_HEADER, "{\"message\": \"Can't find required file.\"}");
			return;
		}

		unsigned char buffer[1024];
		size_t readSize = 0;
		
		mg_printf(c, "HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nTransfer-Encoding: chunked\r\n\r\n", "");

		do
		{
			readSize = fread(buffer, sizeof(char), 1024, fp);

			if(readSize > 0)
			{
				mg_printf(c, "%X\r\n", (unsigned int)readSize);
				mg_send(c, buffer, readSize);
				mg_send(c, "\r\n", 2);
			}
		}while(readSize > 0);

		mg_printf(c, "0\r\n\r\n");

		fclose(fp);
		return;
	}

	mg_http_reply(c, 501, JSON_TYPE_HEADER, "{\"message\": \"Get Request\"}");
}

static void HandleRequest(struct mg_connection* c, int ev, void* ev_data)
{
	if(ev == MG_EV_HTTP_MSG)
	{
		struct mg_http_message* hm = (struct mg_http_message*)ev_data;
		
		char* url = GetStringFromMG(hm->uri); 
		
		if(!mg_strcasecmp(hm->method, mg_str("GET")))
		{	
			HandleGet(c, hm, url);
		}
		else if(!mg_strcasecmp(hm->method, mg_str("POST")))
		{
			HandlePost(c, hm, url);
		}
		else if(!mg_strcasecmp(hm->method, mg_str("PUT")))
		{
			HandlePut(c, hm, url);
		}
		else if(!mg_strcasecmp(hm->method, mg_str("DELETE")))
		{
			HandleDelete(c, hm, url);
		}

		Set(pool, (void*)url);
	}
}

void StartServer(struct mg_mgr* mgr, char* portURL)
{
	struct mg_connection* connection = mg_http_listen(mgr, portURL, HandleRequest, NULL);

	if(connection == NULL)
	{
		WriteLog("In StartServer, line 759: Can't start Server! Please check the settings.\n");
		exit(1);
	}

	size_t sizes[] = { 1, 8, 32, 51, 256, 512 };
	pool = InitPool(6, sizes);

	printf("HTTP Server is connected! Port: %s\n", portURL);
}

void StopServer(struct mg_mgr* mgr)
{
	mg_mgr_free(mgr);
}
