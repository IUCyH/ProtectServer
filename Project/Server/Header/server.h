#ifndef SERVER_H

# define SERVER_H

#include <stdio.h>
#include <microhttpd.h>

static enum MHD_Result HandleRequest(void* cls,
							  struct MHD_Connection* connection,
						      const char* url,
							  const char* method,
							  const char* version,
							  const char* upload_data,
							  size_t* upload_data_size,
							  void** con_cls);
void StartServer(unsigned short port);
void StopServer();

#endif
