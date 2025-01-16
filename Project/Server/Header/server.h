#ifndef SERVER_H

# define SERVER_H

#include <stdio.h>
#include "mongoose.h"

void StartServer(struct mg_mgr* mgr, char* portURL);
void StopServer(struct mg_mgr* mgr);

#endif
