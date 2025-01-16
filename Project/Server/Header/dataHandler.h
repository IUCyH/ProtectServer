#ifndef DATA_HANDLER_H

# define DATA_HANDLER_H

#include <stdio.h>
#include <mariadb/mysql.h>
#include "memoryPool.h"

void OpenDB();
void CloseDB();

int StartTransaction();
int EndTransaction();
void StopTransaction(MYSQL_STMT* stmt);

int ExecuteQuery(MYSQL_STMT* stmt);
int FetchQueryResult(MYSQL_STMT* stmt);
void EndQuery(MYSQL_STMT* stmt);

enum enum_field_types GetBufferType(const char* table, const char* column);
MYSQL_RES* GetMetadata(MYSQL_STMT* stmt);
unsigned long GetColumnCount(MYSQL_RES* metadata);
MYSQL_FIELD* GetFields(MYSQL_RES* metadata);

void MakeBindString(MYSQL_BIND* bind, Pool* pool, const char* value, unsigned long bufferSize);
void MakeBindInt(MYSQL_BIND* bind, Pool* pool, int* value);
void MakeBindNULL(MYSQL_BIND* bind, Pool* pool, enum enum_field_types bufferType);

MYSQL_STMT* MakeDeleteSTMT(const char* table, const char* whereValues);
MYSQL_STMT* MakeUpdateSTMT(const char* table, const char* setValues, const char* whereValues);
MYSQL_STMT* MakeInsertSTMT(const char* table, const char* columns, const char* values);
MYSQL_STMT* MakeSelectSTMT(const char* table, const char* whereValues);
MYSQL_STMT* MakeSelectWithColumnsSTMT(const char* columns, const char* table, const char* whereValues);
MYSQL_STMT* MakeExistSTMT(const char* table, const char* whereValues);

void BindSTMT(MYSQL_STMT* stmt, MYSQL_BIND* paramBind, MYSQL_BIND* resultBind);
void BindSTMTParam(MYSQL_STMT* stmt, MYSQL_BIND* paramBind);
void BindSTMTResult(MYSQL_STMT* stmt, MYSQL_BIND* resultBind);

void ClearBinds(MYSQL_BIND* bind, Pool* pool, int count);
void ClearMetadata(MYSQL_RES* metadata);

#endif
