#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "server.h"
#include "dataHandler.h"

#define PORT 8080

int main()
{
	int sig = 0;
	sigset_t sigset;

	sigemptyset(&sigset);
	sigaddset(&sigset, SIGINT);
	sigaddset(&sigset, SIGTERM);
	pthread_sigmask(SIG_BLOCK, &sigset, NULL);

	StartServer(PORT);
	OpenDB();

	sigwait(&sigset, &sig);

	CloseDB();
	StopServer();

	return 0;
}
