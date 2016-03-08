CC=gcc
CFLAGS=-O3
LDLIBS=-lcapstone -lsqlite3
TARGET=sqlitetrace
SOURCES=sqlitetrace.c
OBJECTS=$(SOURCES:.c=.o)
PREFIX=/usr/local

.PHONY: default all clean check install uninstall

all: $(TARGET) 

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $< -o $@ $(LDLIBS)

clean:
	@-rm -f *.o $(TARGET)

install:
	@cp $(TARGET) $(PREFIX)/bin/

uninstall:
	@rm $(PREFIX)/bin/$(TARGET)CC=gcc
