# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .o
PROGRAM ?= lcsync
INSTALL := install
INSTALL_PROGRAM := $(INSTALL)
prefix ?= /usr/local
exec_prefix := $(prefix)
bindir := $(exec_prefix)/bin
CFLAGS += -I../blake3
#LDFLAGS += -lsodium -lm -pthread -llibrecast -L../blake3 -lblake3
LDFLAGS += -lsodium -lm -pthread -llibrecast
#OBJS = $(PROGRAM).o arg.o file.o globals.o hash.o help.o job.o log.o misc.o mld.o mtree.o net.o opt.o vec.o
OBJS_BLAKE3 := ../blake3/blake3.c ../blake3/blake3_dispatch.c ../blake3/blake3_portable.c $(wildcard ../blake3/*.o)
OBJS = $(PROGRAM).o arg.o file.o globals.o hash.o help.o job.o log.o misc.o mld.o mtree.o net.o opt.o vec.o $(OBJS_BLAKE3)

all:		$(PROGRAM)

$(PROGRAM):	$(OBJS)
		$(CC) $(CFLAGS) $(EXTRAFLAGS) $^ -o $(PROGRAM) $(LDFLAGS)

misc.o:		misc.h

install:        all
		$(INSTALL) -d $(DESTDIR)$(bindir)
		$(INSTALL_PROGRAM) $(PROGRAM) $(DESTDIR)$(bindir)/$(PROGRAM)
		setcap cap_net_raw=eip $(DESTDIR)$(bindir)/$(PROGRAM)

.PHONY: clean realclean

clean:
	rm -f *.o

realclean: clean
	rm -f $(PROGRAM)
