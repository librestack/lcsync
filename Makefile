# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

CFLAGS := -Wall -Wextra -Wpedantic -g
CFLAGS-CLANG := -Wno-gnu-zero-variadic-macro-arguments
export CFLAGS
INSTALLDIR := /usr/local/bin
export INSTALLDIR
PROGRAM := lcsync
export PROGRAM

.PHONY: all clean src test check install net-setup net-teardown

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

net-setup:
	ip link add veth0 type veth peer name veth1
	ip netns add vnet0
	ip netns add vnet1
	ip link set veth0 netns vnet0
	ip link set veth1 netns vnet1
	ip -n vnet0 link set veth0 up
	ip -n vnet1 link set veth1 up
	ip netns show

net-teardown:
	ip -n vnet0 link set veth0 down
	ip -n vnet1 link set veth1 down
	ip -n vnet1 link set veth1 netns vnet0
	ip -n vnet0 link del veth0 type veth peer name veth1
	ip netns del vnet0
	ip netns del vnet1
	ip netns show
