# SPDX-License-Identifier: GPL-2.0

CC=gcc
CXX=g++
CFLAGS=-std=gnu11 -O2 -W -Wall -Wextra -Wno-unused-parameter -Wshadow -I../lib/
ifeq ("$(DEBUG)","1")
  CFLAGS += -g -fsanitize=address -fsanitize=leak -static-libasan
endif

CXXFLAGS=-I../lib/ -I../

include ../Makefile.deps

TOOL:=../ynl-gen-cpp.py

GENS_PATHS=$(shell grep -nrI --files-without-match \
		'protocol: netlink' ../Documentation/netlink/specs/)
GENS_PATHS+=$(wildcard ../Documentation/netlink/specs/rt-*.yaml)
GENS_ALL=$(patsubst ../Documentation/netlink/specs/%.yaml,%,${GENS_PATHS})
GENS=$(filter-out devlink ovs_datapath ovs_flow ovs_vport nlctrl,${GENS_ALL})
SRCS=$(patsubst %,%-user.cpp,${GENS})
HDRS=$(patsubst %,%-user.hpp,${GENS})
OBJS=$(patsubst %,%-user.cpp.o,${GENS})
LIBS=$(patsubst %,%_lib.a,${GENS})


include $(wildcard *.d)

ifeq ($(V),1)
Q =
else
Q = @
endif

all: $(LIBS)
	@echo -e "\tAR libynl.a"
	$(Q)ar rcs libynl.a $(OBJS)

%-user.hpp: ../Documentation/netlink/specs/%.yaml $(TOOL)
	@echo -e "\tGEN $@"
	$(Q)$(TOOL) --mode user --header --spec $< -o $@ $(YNL_GEN_ARG_$*)

%-user.cpp: ../Documentation/netlink/specs/%.yaml $(TOOL)
	@echo -e "\tGEN $@"
	$(Q)$(TOOL) --mode user --source --spec $< -o $@ $(YNL_GEN_ARG_$*)

%-user.cpp.o: %-user.cpp %-user.hpp
	@echo -e "\tCXX $@ "
	$(Q)$(COMPILE.cpp) $(CFLAGS_$*) -MMD -c -o $@ $<

clean:
	rm -f *.o *.d *~

distclean: clean
	rm -f *.a

%_lib.a: $@ %-user.cpp.o
	@echo -e "\tAR $@"
	$(Q)ar rcs $@ $<

.PHONY: all clean distclean
.DEFAULT_GOAL=all
