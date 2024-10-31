CC = gcc
CFLAGS = $(shell pkg-config --cflags libmicrohttpd libcjson libmariadb libjwt libcurl) -ILogin/Header -IServer/Header
LDFLAGS = $(shell pkg-config --libs libmicrohttpd libcjson libmariadb libjwt libcurl)
OBJ_DIR = ObjectFiles
SERVER_SRC_DIR = Server
LOGIN_SRC_DIR = Login

vpath %.c $(SERVER_SRC_DIR) $(LOGIN_SRC_DIR)
vpath %.h $(SERVER_SRC_DIR)/Header $(LOGIN_SRC_DIR)/Header

TARGET = ProtectWAS
SRCS = main.c server.c dataHandler.c authenticator.c tokenProvider.c googleJWTInfoGenerator.c
OBJS = $(patsubst %.c, $(OBJ_DIR)/%.o, $(SRCS))

$(TARGET): $(OBJ_DIR) $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

$(OBJ_DIR):
	mkdir -v $(OBJ_DIR)

$(OBJ_DIR)/%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
