# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (c) 2020-2021 Brett Sheffield <bacs@librecast.net>

SHELL := /bin/bash
CAPS = ""
CFLAGS += -O2 -Wall -Wextra -Wpedantic -g -fno-builtin-malloc -fno-builtin-calloc
NOTOBJS := ../src/$(PROGRAM).o ../src/mdextest.o
OBJS := test.o falloc.o $(filter-out $(NOTOBJS), $(wildcard ../src/*.o))
LDFLAGS := -lm -ldl -pthread -llibrecast -llmdb
BOLD := "\\e[0m\\e[2m"
RESET := "\\e[0m"
PASS = "\\e[0m\\e[32mOK\\e[0m" # end bold, green text
SKIP = "----- requires capabilities \(skipping\) -----\\e[0m"
FAIL = "\\e[0m\\e[31mFAIL\\e[0m" # end bold, red text
LEAK = "\\e[0m\\e[31mFAIL \| LEAK\\e[0m\\n\\tSee $@.valgrind"
LASTLOG := lastlog.log
LOGFILE := $(shell mktemp "lsdb-test-XXXXXXXX.log")
TIMESTAMP = $(shell date +"%Y-%m-%d %H:%M:%S")
VALGRIND = valgrind --leak-check=full --error-exitcode=2 --errors-for-leak-kinds=all --track-origins=yes --log-file=$@.valgrind

.PHONY: test clean realclean build result check cap

cap: SKIP = "----- capabilities not required \(skipping\) -----\\e[0m"
#cap: test
cap: 0000-0046.test 0000-0047.test 0000-0051.test 0000-0058.test 0000-0060.test 0000-0061.test 0000-0062.test 0000-0064.test 0000-0065.test 0000-0066.test 0000-0067.test 0000-0069.test

check: MEMCHECK = $(VALGRIND)
check: FAIL = $(LEAK)
check: test

sanitize: CFLAGS += -fsanitize=address -fno-omit-frame-pointer
sanitize: test

test: clean build $(shell echo ????-????.c | sed 's/\.c/\.test/g') result

build:
	cd ../src && $(MAKE)
	@echo -e "$(TIMESTAMP) - starting tests" >> $(LOGFILE)
	@echo -e "\nRunning tests"

0000-0027.%: LDFLAGS += -lbsd

#0000-0046.%: SHELL = capsh --is-uid=0 --caps=cap_net_raw+eip -- -c
0000-0046.%: CAPS = cap_net_raw=eip
0000-0047.%: CAPS = cap_net_raw=eip
0000-0051.%: CAPS = cap_net_raw=eip
0000-0058.%: CAPS = cap_net_raw=eip
0000-0060.%: CAPS = cap_net_raw=eip
0000-0061.%: CAPS = cap_net_raw=eip
0000-0062.%: CAPS = cap_net_raw=eip
0000-0064.%: CAPS = cap_net_raw=eip
0000-0065.%: CAPS = cap_net_raw=eip
0000-0066.%: CAPS = cap_net_raw=eip
0000-0067.%: CAPS = cap_net_raw=eip
0000-0069.%: CAPS = cap_net_raw=eip
0000-0070.%: CAPS = cap_net_raw=eip

%.test %.clang: %.c $(OBJS)
	@$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	@if [[ $EUID -eq 0 && -n $(CAPS) ]]; then setcap $(CAPS) $@; fi
	@echo -ne "\e[2m" $* " "
	@echo -ne "\n== $@" >> $(LOGFILE)
	@if [[ (-n $(CAPS) && $EUID -ne 0) || (-z $(CAPS) && $EUID -eq 0) ]]; then echo -e "$(SKIP)"; else $(MEMCHECK) ./$@ 2>> $(LOGFILE) && echo -e " $(PASS)" || echo -e " $(FAIL)"; fi
	@ln -sf $(LOGFILE) $(LASTLOG)
	@rm $@
	@$(eval tests_run=$(shell echo $$(($(tests_run)+1))))

%.check: MEMCHECK = $(VALGRIND)
%.check: FAIL = $(LEAK)
%.check: %.test
	@echo "check completed"
	@echo -e "    logfile:   " $(BOLD) $(LOGFILE) / $(LASTLOG) $(RESET)
	@echo -e "    valgrind:  " $(BOLD) "$^.valgrind" $(RESET)

%.debug: MEMCHECK = gdb
%.debug: %.test
	@echo "exiting debugger"

test.o: test.h

result:
	@echo -e "\n$(TIMESTAMP) - tests done" >> $(LOGFILE)
	@echo -e "$(tests_run) tests run\nlogfile: $(LOGFILE)\n"

clean:
	rm -f *.test *.o
	@rm -f $(LOGFILE) $(LASTLOG)

realclean: clean
	rm -f lsdb-test-????????.log* ????-????.test.valgrind
	rm -rf ????-????.tmp.* *core*
	rm -rf ????-????.???.tmp*
