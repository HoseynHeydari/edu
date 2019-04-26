CC=gcc

CFLAGS= -Wall
LFLAGS= -lpcap

TARGET= libfindrtp
ALL= libfindrtp test

all: $(TARGET)

clean:
	rm -f $(ALL) core *.o *.so *~

install: libfindrtp
	install -m 755 libfindrtp.so /usr/lib
	install -m 755 libfindrtp.h /usr/include
	ldconfig
	@echo
	@echo "libfindrtp installed!"
	@echo

uninstall:
	rm /usr/lib/libfindrtp.so
	rm /usr/include/libfindrtp.h
	ldconfig
	@echo
	@echo "libfindrtp uninstalled!"
	@echo

# The library
libfindrtp: libfindrtp.o packet.o sccp.o sip.o
	@echo
	@echo "Creating libfindrtp shared library..."
	$(CC) -shared -o libfindrtp.so libfindrtp.o packet.o sccp.o sip.o $(LFLAGS)

# Library objects 
libfindrtp.o: libfindrtp.c libfindrtp.h
	@echo "Creating libfindrtp object..."
	$(CC) -fPIC $(CFLAGS) -c libfindrtp.c

packet.o: packet.c libfindrtp.h
	@echo "Compiling packet object..."
	$(CC) -fPIC $(CFLAGS) -c packet.c

sccp.o: sccp.c libfindrtp.h
	@echo "Compiling sccp object..."
	$(CC) -fPIC $(CFLAGS) -c sccp.c

sip.o: sip.c libfindrtp.h
	@echo "Compiling sip object..."
	$(CC) -fPIC $(CFLAGS) -c sip.c

# Test app
test: libfindrtp test.o
	@echo "Compiling test app."
	$(CC) $(CFLAGS) -o $@ test.o libfindrtp.so

test.o: test.c libfindrtp.h
	@echo "Compiling test object..."
	$(CC) $(CFLAGS) -c test.c
