# GIT_DESC is provided by external include
include version.mk

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

TOOL_CXXFLAGS+=-DGIT_DESC=\"$(GIT_DESC)\"

ifdef MONGOSUPPORT
TOOL_CXXFLAGS+=-pthread -DMONGOSUPPORT
TOOL_LIBS+=-lmongoclient -lboost_thread -lboost_filesystem -lboost_program_options -lboost_system -lssl -lcrypto
TOOL_LDFLAGS+=-pthread
endif

# If libmongoclient.a for i386 is only available locally, define MONGOPATH32
ifdef MONGOPATH32
TOOL_LIBS+=-L $(MONGOPATH32)
endif

all: ia32 intel64

ia32:
	mkdir -p obj-ia32
	$(MAKE) TARGET=ia32    MONGOSUPPORT=1 MONGOPATH32=mongo_i386 obj-ia32/Tracer.so

intel64:
	mkdir -p obj-intel64
	$(MAKE) TARGET=intel64 MONGOSUPPORT=1 obj-intel64/Tracer.so

clean-all:
	$(MAKE) TARGET=ia32    clean
	$(MAKE) TARGET=intel64 clean
