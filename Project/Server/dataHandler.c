#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <mariadb/mysql.h>
#include "queue.h"
#include "memoryPool.h"
#include "dataHandler.h"

static MYSQL* conn;

void OpenDB()
{
	const char* host = "protectmeios_DB";
	const char* user = "root";
	const char* password = "rootroot";
	const char* db = "protect_me";

	conn = mysql_init(NULL);

	if(conn == NULL)
	{
		fprintf(stderr, "conn is NULL.\n");
		exit(1);
	}

	if(mysql_real_connect(conn, host, user, password, db, 3306, NULL, 0) == NULL)
	{
		fprintf(stderr, "Database connect error: %s\n", mysql_error(conn));
		exit(1);
	}
}

void CloseDB()
{
	mysql_close(conn);
}

int StartTransaction()
{
	if(!mysql_autocommit(conn, 0))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

int EndTransaction()
{
	if(!mysql_commit(conn))
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

void StopTransaction(MYSQL_STMT* stmt)
{
	mysql_rollback(conn);
	EndQuery(stmt);
}

int ExecuteQuery(MYSQL_STMT* stmt)
{
	int status = mysql_stmt_execute(stmt);
	if(status == 0)
	{
		return 1;
	}
	else
	{
		printf("Code: %d\n", status);
		printf("\n%s\n", mysql_stmt_error(stmt));
		return 0;
	}
}

int FetchQueryResult(MYSQL_STMT* stmt)
{
	mysql_stmt_store_result(stmt);
	
	if(!mysql_stmt_fetch(stmt))
	{
		return 1;
	}
	else
	{
		printf("\n%s\n", mysql_stmt_error(stmt));
		return 0;
	}
}

void EndQuery(MYSQL_STMT* stmt)
{
	mysql_stmt_close(stmt);
}

enum enum_field_types GetBufferType(const char* table, const char* column)
{
	char* query = "SELECT DATA_TYPE FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME = '%s' AND COLUMN_NAME = '%s'";
	char result[256];
	enum enum_field_types type = MYSQL_TYPE_NULL;
	MYSQL_RES* queryResult = NULL;
    MYSQL_ROW row;

	sprintf(result, query, table, column);
	
	if(mysql_query(conn, result))
	{
		fprintf(stderr, "%s\n", mysql_error(conn));
		return MYSQL_TYPE_NULL;
	}

	queryResult = mysql_store_result(conn);
	if(queryResult == NULL)
	{
		fprintf(stderr, "%s\n", mysql_error(conn));
		return MYSQL_TYPE_NULL;
	}

	row = mysql_fetch_row(queryResult);
	if(row != NULL)
	{
		if(!strcmp(row[0], "int"))
		{
			type = MYSQL_TYPE_LONG;
		}
		else if(!strcmp(row[0], "varchar"))
		{
			type = MYSQL_TYPE_STRING;
		}
	}

	mysql_free_result(queryResult);
	return type;
}

MYSQL_RES* GetMetadata(MYSQL_STMT* stmt)
{
	return mysql_stmt_result_metadata(stmt);
}

unsigned long GetColumnCount(MYSQL_RES* metadata)
{
	return mysql_num_fields(metadata);
}

MYSQL_FIELD* GetFields(MYSQL_RES* metadata)
{
	return mysql_fetch_fields(metadata);
}

void MakeBindString(MYSQL_BIND* bind, Pool* pool, const char* value, unsigned long bufferSize)
{
	size_t* length = Get(pool, sizeof(size_t));
	my_bool* isNULL = Get(pool, sizeof(my_bool));

	*length = strlen(value);
	*isNULL = false;

	memset(bind, 0, sizeof(MYSQL_BIND));

	bind->buffer_type = MYSQL_TYPE_STRING;
	bind->buffer = (char*)value;
	bind->buffer_length = bufferSize;
	bind->length = length;
	bind->is_null = isNULL;
}

void MakeBindInt(MYSQL_BIND* bind, Pool* pool, int* value)
{
	my_bool* isNULL = Get(pool, sizeof(my_bool));
	*isNULL = false;

	memset(bind, 0, sizeof(MYSQL_BIND));

	bind->buffer_type = MYSQL_TYPE_LONG;
	bind->buffer = (char*)value;
	bind->buffer_length = sizeof(int);
	bind->is_null = isNULL;
}

void MakeBindNULL(MYSQL_BIND* bind, Pool* pool, enum enum_field_types bufferType)
{
	my_bool* isNULL = Get(pool, sizeof(my_bool));
	*isNULL = true;

	memset(bind, 0, sizeof(MYSQL_BIND));

	bind->buffer_type = bufferType;
	bind->buffer = NULL;
	bind->is_null = isNULL;
}

MYSQL_STMT* MakeDeleteSTMT(const char* table, const char* whereValues)
{
	char* query = "DELETE FROM %s WHERE %s";
	char result[(strlen(query) - 4 + strlen(table) + strlen(whereValues) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, table, whereValues);

	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);

	return stmt;
}

MYSQL_STMT* MakeUpdateSTMT(const char* table, const char* setValues, const char* whereValues)
{
	char* query = "UPDATE %s SET %s WHERE %s";
	char result[(strlen(query) - 6 + strlen(table) + strlen(setValues) + strlen(whereValues) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, table, setValues, whereValues);

	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);

	return stmt;
}

MYSQL_STMT* MakeInsertSTMT(const char* table, const char* columns, const char* values)
{
	char* query = "INSERT INTO %s (%s) VALUES (%s)";
	char result[(strlen(query) - 6 + strlen(table) + strlen(columns) + strlen(values) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, table, columns, values);

	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);

	return stmt;
}

MYSQL_STMT* MakeSelectSTMT(const char* table, const char* whereValues)
{
	char* query = "SELECT * FROM %s WHERE %s";
	char result[(strlen(query) - 4 + strlen(table) + strlen(whereValues) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, table, whereValues);
	
	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);
	
	return stmt;
}

MYSQL_STMT* MakeSelectWithColumnsSTMT(const char* columns, const char* table, const char* whereValues)
{
	char* query = "SELECT %s FROM %s WHERE %s";
	char result[(strlen(query) - 6 + strlen(columns) + strlen(table) + strlen(whereValues) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, columns, table, whereValues);
	
	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);
	
	return stmt;
}

MYSQL_STMT* MakeExistSTMT(const char* table, const char* whereValues)
{
	char* query = "SELECT EXISTS (SELECT 1 FROM %s WHERE %s)";
	char result[(strlen(query) - 4 + strlen(table) + strlen(whereValues) + 1)];
	MYSQL_STMT* stmt = NULL;

	sprintf(result, query, table, whereValues);

	stmt = mysql_stmt_init(conn);
	mysql_stmt_prepare(stmt, result, -1);

	return stmt;
}

void BindSTMT(MYSQL_STMT* stmt, MYSQL_BIND* paramBind, MYSQL_BIND* resultBind)
{
	mysql_stmt_bind_param(stmt, paramBind);
	mysql_stmt_bind_result(stmt, resultBind);
}

void BindSTMTParam(MYSQL_STMT* stmt, MYSQL_BIND* paramBind)
{
	mysql_stmt_bind_param(stmt, paramBind);
}

void BindSTMTResult(MYSQL_STMT* stmt, MYSQL_BIND* resultBind)
{
	mysql_stmt_bind_result(stmt, resultBind);
}

void ClearBinds(MYSQL_BIND* bind, Pool* pool, int count)
{
	for(int i = 0; i < count; i++)
	{
		if(bind[i].buffer_type == MYSQL_TYPE_STRING)
		{
			if(bind[i].buffer != NULL)
			{
				Set(pool, (void*)bind[i].buffer);
			}
			
			if(bind[i].length != NULL)
			{
				Set(pool, (void*)bind[i].length);
			}

			if(bind[i].is_null != NULL)
			{
				Set(pool, (void*)bind[i].is_null);
			}
		}
		else if(bind[i].buffer_type == MYSQL_TYPE_LONG)
		{
			if(bind[i].buffer != NULL)
			{
				Set(pool, (void*)bind[i].buffer);
			}

			if(bind[i].is_null != NULL)
			{
				Set(pool, (void*)bind[i].is_null);
			}
		}
	}
}

void ClearMetadata(MYSQL_RES* metadata)
{
	mysql_free_result(metadata);
}
