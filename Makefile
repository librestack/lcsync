# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

CFLAGS := -Wall -Wextra -Wpedantic -g
CFLAGS-CLANG := $(CFLAGS) -Wno-gnu-zero-variadic-macro-arguments
export CFLAGS
INSTALLDIR := /usr/local/bin
export INSTALLDIR
PROGRAM := lcsync
export PROGRAM

.PHONY: all clean src test check install

all: src

install: all
	cd src && $(MAKE) $@

src:
	$(MAKE) -C $@

clean realclean:
	cd src && $(MAKE) $@
	cd test && $(MAKE) $@

sparse: clean
	CC=cgcc $(MAKE) src

clang: clean
	CC=clang $(MAKE) CFLAGS="$(CFLAGS-CLANG)" src

gcc: clean all

check test sanitize: src
	cd test && $(MAKE) $@

%.test %.check:
	cd test && $(MAKE) -B $@
