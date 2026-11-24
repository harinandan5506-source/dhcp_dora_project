# Builds on Linux (gcc) and on Windows (MinGW-w64: mingw32-make)
CC      = gcc
CFLAGS  = -std=gnu11 -Wall -Wextra -Werror -O2

ifeq ($(OS),Windows_NT)
  EXE    = .exe
  LDLIBS = -lws2_32
  RMF    = del /Q /F
else
  EXE    =
  LDLIBS =
  RMF    = rm -f
endif

TARGETS = dhcp_server$(EXE) dhcp_client$(EXE)

.PHONY: all test clean

all: $(TARGETS)

dhcp_server$(EXE): dhcp_server.c dhcp_common.h
	$(CC) $(CFLAGS) -o $@ dhcp_server.c $(LDLIBS)

dhcp_client$(EXE): dhcp_client.c dhcp_common.h
	$(CC) $(CFLAGS) -o $@ dhcp_client.c $(LDLIBS)

test: all
ifeq ($(OS),Windows_NT)
	powershell -NoProfile -ExecutionPolicy Bypass -File test.ps1
else
	./test.sh
endif

clean:
	-$(RMF) $(TARGETS)
