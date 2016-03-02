CC=gcc
CPPFLAGS=-O3
LDLIBS=-lcapstone
SOURCES=texttrace.c
OBJECTS=$(SOURCES:.c=.o)

all: $(SOURCES) texttrace

install: all
	cp texttrace /usr/local/bin/
