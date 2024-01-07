CFLAGS = -O0 -g -I /opt/local/include -L /opt/local/lib 
LDFLAGS = -L /opt/local/lib -lcrypto
CC = gcc

DEPS = config.h getpassword.h utils.h
OBJ = config.o getpassword.o utils.o minisecsrv.o

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

minisecsrv: $(OBJ)
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -rf *.o minisecsrv
