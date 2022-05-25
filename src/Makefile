# SPDX-License-Identifier: GPL-2.0-only OR GPL-3.0-only
# Copyright (c) 2020-2022 Brett Sheffield <bacs@librecast.net>

SHELL = /bin/sh
.SUFFIXES:
.SUFFIXES: .c .o
PROGRAM ?= lcsync
INSTALL := install
INSTALL_PROGRAM := $(INSTALL)
prefix ?= /usr/local
exec_prefix := $(prefix)
bindir := $(exec_prefix)/bin
LDFLAGS += -lm -pthread -llibrecast
OBJS = $(PROGRAM).o arg.o file.o globals.o help.o job.o log.o mdex.o misc.o mld.o mtree.o net.o opt.o vec.o
SETCAP_PROGRAM ?= setcap

all:		$(PROGRAM)

$(PROGRAM):	$(OBJS)
		$(CC) $(CFLAGS) $(EXTRAFLAGS) $^ -o $(PROGRAM) $(LDFLAGS)

misc.o:		misc.h

install:        all
		$(INSTALL) -d $(DESTDIR)$(bindir)
		$(INSTALL_PROGRAM) $(PROGRAM) $(DESTDIR)$(bindir)/$(PROGRAM)
		$(SETCAP_PROGRAM) cap_net_raw=eip $(DESTDIR)$(bindir)/$(PROGRAM)

.PHONY: clean realclean setcap

clean:
	rm -f *.o

realclean: clean
	rm -f $(PROGRAM)

setcap: $(PROGRAM)
	setcap cap_net_raw=eip $(PROGRAM)
