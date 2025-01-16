CC = gcc
CFLAGS = $(shell pkg-config --cflags libcjson libmariadb libjwt libcurl libargon2) -ILogin/Header -IServer/Header -IUtil/Header  -IHeader
LDFLAGS = $(shell pkg-config --libs libcjson libmariadb libjwt libcurl libargon2)
OBJ_DIR = ObjectFiles
SERVER_SRC_DIR = Server
LOGIN_SRC_DIR = Login
UTIL_SRC_DIR = Util

vpath %.c $(SERVER_SRC_DIR) $(LOGIN_SRC_DIR) $(UTIL_SRC_DIR)
vpath %.h $(SERVER_SRC_DIR)/Header $(LOGIN_SRC_DIR)/Header $(UTIL_SRC_DIR)/Header /Header

TARGET = ProtectWAS
SRCS = mongoose.c  main.c server.c dataHandler.c authenticator.c tokenProvider.c tokenAnalyzer.c googleJWTInfoGenerator.c linkedList.c queue.c memoryPool.c
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))

$(TARGET): $(OBJ_DIR) $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

$(OBJ_DIR):
	mkdir -v $(OBJ_DIR)

$(OBJ_DIR)/%.o: %.c
	$(CC) -g -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
