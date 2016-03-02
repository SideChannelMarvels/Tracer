CC=gcc
CPPFLAGS=-O3 -I/usr/local/include/libmongoc-1.0 -I/usr/local/include/libbson-1.0
LDLIBS=-lcapstone -lmongoc-1.0 -lbson-1.0
SOURCES=mongotrace.c
OBJECTS=$(SOURCES:.c=.o)

all: $(SOURCES) mongotrace

install: mongotrace
	cp mongotrace /usr/local/bin
