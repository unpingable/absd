# Base userland ports (userland/README.md). Invoked by scripts/build-userland.sh
# with ROOT (the platform tree), SRC (the patched copy of the staged sbase
# tree), UP (the staged upstream root, for the prefix map), OUT (the build
# directory), SIDE=absd|linux and, for absd, CC_ABSD and POSIX_A.
# Objects go under $(OUT)/obj/$(SIDE), products under $(OUT)/$(SIDE).
#
# Both sides compile the same patched sources with sbase's own CPPFLAGS and
# the userland include directory (one wrapper header, README "Build
# adaptations"). The ABSD side adds ABSD_NO_MTIME (C-INTERFACE.md 11: no
# modification time reaches a program; test-access-mtime.patch) and
# ABSD_NO_SIGNALS (no signal is delivered, CPA-004; ed-absd.patch) and
# ABSD_NO_UMASK (no creation mask; find-absd.patch's link-only stub), and links
# each utility through absd-cc with sbase's libutil.a and libutf.a and the
# adapter's libabsd-posix.a, as the cports Makefile links its ports
# (Picolibc's strerror hook is the kit's since R13, c/libabs/strerror_hook.c). The Linux side is the host-gcc REFERENCE build of the
# same sources against glibc.
# The ABSD archiver is $(ABSD_AR), default llvm-ar-18 (as the kit names
# clang-18 through ABSD_CLANG).
ROOT ?= $(error set ROOT)
SRC ?= $(error set SRC)
UP ?= $(error set UP)
OUT ?= $(error set OUT)
SIDE ?= $(error set SIDE)
UTILS := printf test grep sort sed od cmp ed find diff hexdump tar
TOYBOX_UTILS := diff hexdump
TOYBOX_SRC ?= $(OUT)/toybox-src
CPPFLAGS := -D_DEFAULT_SOURCE -D_NETBSD_SOURCE -D_BSD_SOURCE -D_XOPEN_SOURCE=700 -D_FILE_OFFSET_BITS=64
PREFIX_MAP := -ffile-prefix-map=$(SRC)=/sbase -ffile-prefix-map=$(UP)=/upstream -ffile-prefix-map=$(ROOT)=/absd
ROOT_PHYS := $(realpath $(ROOT))
ifneq ($(filter-out $(ROOT),$(ROOT_PHYS)),)
PREFIX_MAP += -ffile-prefix-map=$(ROOT_PHYS)=/absd
endif
FLAGS := -O2 $(CPPFLAGS) -I$(ROOT)/userland/include -I$(SRC) $(PREFIX_MAP)
LIBUTF := $(notdir $(basename $(wildcard $(SRC)/libutf/*.c)))
LIBUTIL := $(notdir $(basename $(wildcard $(SRC)/libutil/*.c)))
O := $(OUT)/obj/$(SIDE)
B := $(OUT)/$(SIDE)
ifeq ($(SIDE),absd)
CC_ABSD ?= $(error set CC_ABSD)
POSIX_A ?= $(error set POSIX_A)
CC := $(CC_ABSD)
SIDEFLAGS := -DABSD_NO_MTIME -DABSD_NO_SIGNALS -DABSD_NO_UMASK
ABSD_AR ?= llvm-ar-18
AR := $(ABSD_AR)
else
CC := gcc
SIDEFLAGS :=
AR := ar
endif
.DEFAULT_GOAL := all
all: $(addprefix $(B)/,$(UTILS))
$(O)/libutf/%.o: $(SRC)/libutf/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(FLAGS) $(SIDEFLAGS) -o $@ $<
$(O)/libutil/%.o: $(SRC)/libutil/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(FLAGS) $(SIDEFLAGS) -o $@ $<
$(O)/%.o: $(SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $(FLAGS) $(SIDEFLAGS) -o $@ $<
# D: deterministic archives (no timestamps, uids or modes in the members).
$(O)/libutf.a: $(addprefix $(O)/libutf/,$(addsuffix .o,$(LIBUTF)))
	rm -f $@; $(AR) rcsD $@ $^
$(O)/libutil.a: $(addprefix $(O)/libutil/,$(addsuffix .o,$(LIBUTIL)))
	rm -f $@; $(AR) rcsD $@ $^
ifeq ($(SIDE),absd)
$(B)/%: $(O)/%.o $(O)/libutil.a $(O)/libutf.a $(POSIX_A) | $(B)
	$(CC_ABSD) -o $@ $(O)/$*.o $(O)/libutil.a $(O)/libutf.a $(POSIX_A)
else
$(B)/%: $(O)/%.o $(O)/libutil.a $(O)/libutf.a | $(B)
	gcc -o $@ $(O)/$*.o $(O)/libutil.a $(O)/libutf.a
endif
# These standalone accepted adaptations do not consume sbase helper archives.
$(O)/diff.o: $(TOYBOX_SRC)/diff/diff.c
	@mkdir -p $(dir $@)
	$(CC) -c -std=c11 -O2 -Wall -Wextra -Werror -ffile-prefix-map=$(ROOT)=/absd -ffile-prefix-map=$(TOYBOX_SRC)/diff=/toybox-diff $< -o $@
$(O)/hexdump.o: $(TOYBOX_SRC)/hexdump/hexdump.c
	@mkdir -p $(dir $@)
	$(CC) -c -std=c11 -O2 -Wall -Wextra -Werror -ffile-prefix-map=$(ROOT)=/absd -ffile-prefix-map=$(TOYBOX_SRC)/hexdump=/toybox-hexdump $< -o $@
ifeq ($(SIDE),absd)
$(addprefix $(B)/,$(TOYBOX_UTILS)): $(B)/%: $(O)/%.o $(POSIX_A) | $(B)
	$(CC_ABSD) -o $@ $< $(POSIX_A)
else
$(addprefix $(B)/,$(TOYBOX_UTILS)): $(B)/%: $(O)/%.o | $(B)
	gcc -o $@ $<
endif
$(B):
	mkdir -p $@
.PHONY: all
.SECONDARY:
