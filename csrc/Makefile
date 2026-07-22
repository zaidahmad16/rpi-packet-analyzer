# pktcap: the C capture engine for pktan.
#   make          optimised build  -> csrc/pktcap
#   make asan     AddressSanitizer + UBSan build -> csrc/pktcap-asan (for tests)
CC      ?= cc
CFLAGS  ?= -O2 -g
WARN     = -std=c11 -Wall -Wextra -Werror -Wshadow -Wpointer-arith -Wstrict-prototypes

all: pktcap

pktcap: pktcap.c pktcap.h
	$(CC) $(CFLAGS) $(WARN) -o $@ pktcap.c

asan: pktcap-asan
pktcap-asan: pktcap.c pktcap.h
	$(CC) -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer $(WARN) -o $@ pktcap.c

clean:
	rm -f pktcap pktcap-asan

.PHONY: all asan clean
