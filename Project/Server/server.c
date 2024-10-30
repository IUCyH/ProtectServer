#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <microhttpd.h>
#include <cJSON.h>
#include "server.h"

//static ServerContext* serverContext;
static struct MHD_Daemon* serverDaemon;

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
	struct MHD_Response* response = NULL;
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
		response = MHD_create_response_from_buffer(strlen(testStr), (void*)testStr, MHD_RESPMEM_PERSISTENT);

		//MHD_add_response_header(response, "Content-Type", "application/json; charset=utf-8");

		int result = MHD_queue_response(connection, MHD_HTTP_OK, response);
		MHD_destroy_response(response);

		return result;
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
