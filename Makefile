COMMON_OBJS=msg.o netlink.o util.o
CLIENT_OBJS=client.o $(COMMON_OBJS)
SERVER_OBJS=server.o $(COMMON_OBJS)
EXECS=fou-client fou-server
CFLAGS+=-Wall -DBUNDLED_INCLUDES
LIBS=
all: $(EXECS)

fou-client: $(CLIENT_OBJS)
	$(CC) $(CLIENT_OBJS) $(LIBS) -o fou-client

fou-server: $(SERVER_OBJS)
	$(CC) $(SERVER_OBJS) $(LIBS) -o fou-server

clean:
	rm -fr *~ *.o $(EXECS)
