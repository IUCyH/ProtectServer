#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>
#include "server.h"
#include "dataHandler.h"
#include "tokenProvider.h"

#define PORT 8080

char* GetEncryptKey();

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

	//char* email = "ghdckdwn8456@gmail.com";
	//char* uid = "1";
	//char* key = GetEncryptKey();
	//char* token = MakeAccessToken(email, uid,

	sigwait(&sigset, &sig);

	CloseDB();
	StopServer();

	return 0;
}

char* GetEncryptKey()
{
	const int keyLength = 257;
	FILE* fp;
	char* key = (char*)malloc(sizeof(char) * keyLength);

	fp = fopen("/home/ubuntu/ProtectServer/TokenEncryptKey.txt", "r");

	if(fp == NULL)
	{
		fprintf(stderr, "Fail to open file");
		return NULL;
	}

	fgets(key, keyLength, fp);
	free(fp);
	return key;
}
