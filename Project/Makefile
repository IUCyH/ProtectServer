CC = gcc
CFLAGS = $(shell pkg-config --cflags libmicrohttpd libcjson mysqlclient)
LDFLAGS = $(shell pkg-config --libs libmicrohttpd libcjson mysqlclient)

TARGET = ProtectWAS
SRCS = main.c server.c authenticator.c
OBJS = $(SRCS:.c=.o)

$(TARGET): $(OBJS)
	$(CC) -o $(TARGET) $(OBJS) $(LDFLAGS)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS)

clean:
	rm -f $(OBJS) $(TARGET)
