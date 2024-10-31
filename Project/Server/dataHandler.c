#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mariadb/mysql.h>
#include "dataHandler.h"

static MYSQL* conn;

void OpenDB()
{
	const char* host = "localhost";
	const char* user = "root";
	const char* password = "rootroot"; // TODO: 비번 다른곳으로 옮기기
	const char* db = "protect_me";

	conn = mysql_init(NULL);

	if(conn == NULL)
	{
		fprintf(stderr, "conn is NULL.\n");
		exit(1);
	}

	if(mysql_real_connect(conn, host, user, password, db, 9999, NULL, 0) == NULL)
	{
		fprintf(stderr, "Database connect error: %s\n", mysql_error(conn));
		exit(1);
	}
}

void CloseDB()
{
	mysql_commit(conn);
	mysql_close(conn);
}

QueryResult* Search(const char* query)
{
	MYSQL_RES* result = mysql_store_result(conn);
	MYSQL_ROW row;
	QueryResult* queryResult = (QueryResult*)malloc(sizeof(QueryResult));

	queryResult->result = NULL;

	if(!mysql_query(conn, query))
	{
		int index = 0;

		while((row = mysql_fetch_row(result)) != NULL)
		{
			if(queryResult->result == NULL)
			{
				queryResult->rowCount = mysql_num_rows(result);
				queryResult->fieldCount = mysql_num_fields(result);

				queryResult->result = (char***)malloc(sizeof(char**) * queryResult->rowCount);
				for(int i = 0; i < queryResult->rowCount; i++)
				{
					queryResult->result[i] = (char**)malloc(sizeof(char*) * queryResult->fieldCount);
				}
			}

			for(int i = 0; i < queryResult->fieldCount; i++)
			{
				queryResult->result[index][i] = (char*)malloc(sizeof(char) * (strlen(row[i]) + 1));
				strcpy(queryResult->result[index][i], row[i]);
			}

			index++;
		}
	}
	else
	{
		fprintf(stderr, "Can't execute query!");
		return NULL;
	}

	mysql_free_result(result);
	return queryResult;
}
