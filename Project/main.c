#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "server.h"

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

	sigwait(&sigset, &sig);

	StopServer();

	return 0;
}
