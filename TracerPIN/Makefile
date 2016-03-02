# GIT_DESC is provided by external include
include version.mk

CONFIG_ROOT := $(PIN_ROOT)/source/tools/Config
include $(CONFIG_ROOT)/makefile.config
include $(TOOLS_ROOT)/Config/makefile.default.rules

TOOL_CXXFLAGS+=-DGIT_DESC=\"$(GIT_DESC)\"

TOOL_LIBS+=-lsqlite3

all: ia32 intel64

ia32:
	mkdir -p obj-ia32
	$(MAKE) TARGET=ia32    obj-ia32/Tracer.so

intel64:
	mkdir -p obj-intel64
	$(MAKE) TARGET=intel64 obj-intel64/Tracer.so

clean-all:
	$(MAKE) TARGET=ia32    clean
	$(MAKE) TARGET=intel64 clean
