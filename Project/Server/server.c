#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <cJSON.h>
#include "queryGenerator.h"
#include "dataHandler.h"
#include "server.h"

//static ServerContext* serverContext;
static struct MHD_Daemon* serverDaemon;

static enum MHD_Result MakeHttpResult(struct MHD_Connection* connection, char* message, int httpCode)
{
	struct MHD_Response* response = MHD_create_response_from_buffer(strlen(message), (void*)message, MHD_RESPMEM_PERSISTENT);

	MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");

	int result = MHD_queue_response(connection, httpCode, response);
	MHD_destroy_response(response);

	return result;
}

static char* GetRequestType(const char* url)
{
	size_t urlLength = strlen(url);
	size_t unusedWordLength = 4;
	size_t typeLength = urlLength - unusedWordLength;
	char* result = (char*)malloc(sizeof(char) * (typeLength + 1));
	
	strncpy(result, url, typeLength);
	result[typeLength] = '\0';

	return result;
}

static enum MHD_Result HandleGet(struct MHD_Connection* connection, const char* url)
{
	// TODO: Header 검사하기
	char* requestType = GetRequestType(url);
	char* json = (char*)malloc(sizeof(char) * 513);

	if(!strcmp("/user/", requestType))
	{
		char* idString = (char*)MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "user_id");

		if(idString == NULL)
		{
			fprintf(stderr, "Can't get id from url query string!");
			return MakeHttpResult(connection, "Invalid url", MHD_HTTP_BAD_REQUEST);
		}

		int id = atoi(idString);
		char* where = MakeWhereInt("id = %d", id);
		char* query = MakeSelectQuery("User", where);
		
		QueryResult* queryResult = Search(query);
		
		if(queryResult == NULL || queryResult->result == NULL || queryResult->rowCount <= 0 || queryResult->fieldCount < 2 || queryResult->result[0] == NULL || queryResult->result[0][1] == NULL)
		{
			fprintf(stderr, "Query faild\n");

			free(where);
			free(query);
			return MakeHttpResult(connection, "Query faild", MHD_HTTP_NOT_FOUND);
		}
		
		cJSON* obj = cJSON_CreateObject();
		char* name = queryResult->result[0][1];
	
		cJSON_AddNumberToObject(obj, "id", id);
		cJSON_AddStringToObject(obj, "name", name);

		strcpy(json, cJSON_Print(obj));
		
		free(where);
		free(query);
		
		for(int i = 0; i < queryResult->fieldCount; i++)
		{
			free(queryResult->result[0][i]);
		}
		free(queryResult->result[0]);
		free(queryResult);

		cJSON_Delete(obj);
	}

	return MakeHttpResult(connection, json, MHD_HTTP_OK);
}

static enum MHD_Result HandleRequest(void* cls,
							  struct MHD_Connection* connection,
						      const char* url,
							  const char* method,
							  const char* version,
							  const char* upload_data,
							  size_t* upload_data_size,
	 						  void** con_cls)
{
	static int dummy = 0;
	char* testStr = "Hello World!";

	if(*con_cls == NULL)
	{
		*con_cls = &dummy;
		return MHD_YES;
	}

	if(*upload_data_size != 0)
	{
		*upload_data_size = 0;
		return MHD_YES;
	}

	if(!strcmp(method, "GET"))
	{
		return HandleGet(connection, url);
	}

	return MHD_NO;
}

void StartServer(unsigned short port)
{
	serverDaemon = MHD_start_daemon(MHD_USE_SELECT_INTERNALLY, port, NULL, NULL, &HandleRequest, NULL, MHD_OPTION_END);

	if(serverDaemon == NULL)
	{
		fprintf(stderr, "Can't start Server! Please check the settings.\n");
		exit(1);
	}

	printf("HTTP Server is connected! Port: %d\n", port);
}

void StopServer()
{
	MHD_stop_daemon(serverDaemon);
}
