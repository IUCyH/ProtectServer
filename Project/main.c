#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "mongoose.h"
#include "server.h"
#include "dataHandler.h"

#define PORT "http://127.0.0.1:8080"

int serverRunning = 1;
int sig = 0;
sigset_t sigset;

void* signalWaiter(void* arg)
{
	sigwait(&sigset, &sig);

	serverRunning = 0;

	return NULL;
}

int main()
{
	static struct mg_mgr mgr;
	
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	mg_mgr_init(&mgr);

	StartServer(&mgr, PORT);
	OpenDB();

	pthread_t waitThread;
    pthread_create(&waitThread, NULL, signalWaiter, NULL);

	while(serverRunning)
	{
		mg_mgr_poll(&mgr, 100);	
	}

	pthread_join(waitThread, NULL);

	CloseDB();
	StopServer(&mgr);

	return 0;
}
