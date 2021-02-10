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
CFLAGS +=
LDFLAGS += -lsodium -lm -pthread -llibrecast -llcdb -llsdb
OBJS = $(PROGRAM).o arg.o file.o globals.o hash.o help.o job.o log.o misc.o mld.o mtree.o net.o opt.o vec.o

all:		$(PROGRAM)

$(PROGRAM):	$(OBJS)
		$(CC) $(OBJS) -o $@ $(LDFLAGS)

misc.o:		misc.h

$(PROGRAM).o:

install:        all
		$(INSTALL) -d $(DESTDIR)$(bindir)
		$(INSTALL_PROGRAM) $(PROGRAM) $(DESTDIR)$(bindir)/$(PROGRAM)
		setcap cap_net_raw=eip $(DESTDIR)$(bindir)/$(PROGRAM)

.PHONY: clean realclean

clean:
	rm -f *.o

realclean: clean
	rm -f $(PROGRAM)
