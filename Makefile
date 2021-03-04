# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

CFLAGS := -Wall -Wextra -Wpedantic -g
CFLAGS-CLANG := -Wno-gnu-zero-variadic-macro-arguments -I../blake3
export CFLAGS
INSTALLDIR := /usr/local/bin
export INSTALLDIR
PROGRAM := lcsync
export PROGRAM

.PHONY: all clean src test check install blake3

all: src

install: all
	cd src && $(MAKE) $@

blake3:
	$(MAKE) -C blake3 all

src: blake3
	$(MAKE) -C $@

clean realclean:
	$(MAKE) -C src $@
	$(MAKE) -C test $@
	$(MAKE) -C blake3 $@

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

%.test %.check:
	cd test && $(MAKE) -B $@
