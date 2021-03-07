# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

CFLAGS := -Wall -Wextra -Wpedantic -g
CFLAGS-CLANG := -Wno-gnu-zero-variadic-macro-arguments
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
	$(MAKE) -C src $@
	$(MAKE) -C test $@

fixme:
	grep -n FIXME src/*.{c,h} test/*.{c,h}

todo:
	grep -n TODO src/*.{c,h} test/*.{c,h}

sparse: clean
	CC=cgcc $(MAKE) src

clang: clean
	CC=clang $(MAKE) CFLAGS+="$(CFLAGS-CLANG)" src

clangtest: clean
	CC=clang $(MAKE) CFLAGS+="$(CFLAGS-CLANG)" test

gcc: clean all

cap check test sanitize: clean src
	cd test && $(MAKE) $@

%.clang:
	CC=clang $(MAKE) CFLAGS+="$(CFLAGS-CLANG)" -B -C test $@

%.test %.check: clean src
	cd test && $(MAKE) $@
