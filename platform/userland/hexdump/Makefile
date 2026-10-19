# Explicit experimental source-specific build. Not installed until target gates
# and two-build digests are qualified and PORTS.tsv is deliberately advanced.
ROOT ?= $(error set ROOT)
SRC ?= $(error set SRC to stage-hexdump.py output)
OUT ?= $(error set OUT)
SIDE ?= linux
ifeq ($(SIDE),absd)
CC_ABSD ?= $(error set CC_ABSD to an explicitly identified kit compiler)
POSIX_A ?= $(error set POSIX_A to an explicitly identified adapter archive)
CC := $(CC_ABSD)
LDLIBS := $(POSIX_A)
else
CC := gcc
endif
all: $(OUT)/hexdump
$(OUT)/hexdump: $(SRC)/hexdump.c $(ROOT)/userland/hexdump/Makefile
	mkdir -p $(OUT)
	$(CC) -std=c11 -O2 -Wall -Wextra -Werror -ffile-prefix-map=$(ROOT)=/absd -ffile-prefix-map=$(SRC)=/toybox-hexdump $< $(LDLIBS) -o $@
.PHONY: all
