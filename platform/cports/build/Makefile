# Stage-2 ports (CPORTS-HARNESS.md 3). Invoked by scripts/build-cports.sh with
# ROOT (the platform tree), CAMP (its parent), SIDE=absd|linux; UP, OUT and
# CC_ABSD default to the campaign layout under CAMP and are given by
# build-cports.sh from ABSD_CPORTS_UPSTREAM, ABSD_CPORTS_BUILD and
# ABSD_CKIT_BUILD. Upstream
# trees are read in place and never written; objects go under
# $(CAMP)/cports-build/obj/$(SIDE), products under $(CAMP)/cports-build/$(SIDE).
# Each ABSD link also writes $(OBJ)/absd/<product>.objs, the objects it linked,
# from which build-cports.sh derives the product's demand.
ROOT ?= $(error set ROOT)
CAMP ?= $(error set CAMP)
SIDE ?= $(error set SIDE)
UP ?= $(CAMP)/upstream
OUT ?= $(CAMP)/cports-build
OBJ := $(OUT)/obj
BIN_ABSD := $(OUT)/absd
BIN_LINUX := $(OUT)/linux
POSIX_A := $(OUT)/lib/libabsd-posix.a
CC_ABSD ?= $(CAMP)/ckit-build/kit/bin/absd-cc
CC_LINUX := gcc
# Every compile (both sides) maps the staged upstream tree to /upstream and
# the platform tree, as spelled and physically, to /absd: __FILE__ (assert(),
# sqlite's shell.c) and any debug info then name no checkout or campaign
# path, so the products hash the same wherever the tree and UP live.
PREFIX_MAP := -ffile-prefix-map=$(UP)=/upstream -ffile-prefix-map=$(ROOT)=/absd
UP_PHYS := $(realpath $(UP))
ROOT_PHYS := $(realpath $(ROOT))
ifneq ($(filter-out $(UP),$(UP_PHYS)),)
PREFIX_MAP += -ffile-prefix-map=$(UP_PHYS)=/upstream
endif
ifneq ($(filter-out $(ROOT),$(ROOT_PHYS)),)
PREFIX_MAP += -ffile-prefix-map=$(ROOT_PHYS)=/absd
endif
PRODUCTS :=
# The included fragments define targets; `all` is the goal whatever they define first.
.DEFAULT_GOAL := all
include $(ROOT)/cports/build/lua.mk
include $(ROOT)/cports/build/zlib.mk
include $(ROOT)/cports/build/sqlite.mk
include $(ROOT)/cports/build/probe.mk
ifeq ($(SIDE),absd)
all: $(addprefix $(BIN_ABSD)/,$(PRODUCTS))
$(addprefix $(BIN_ABSD)/,$(PRODUCTS)): | $(OBJ)/absd $(BIN_ABSD)
else
all: $(addprefix $(BIN_LINUX)/,$(PRODUCTS))
$(addprefix $(BIN_LINUX)/,$(PRODUCTS)): | $(OBJ)/linux $(BIN_LINUX)
endif
$(OBJ)/absd $(OBJ)/linux $(BIN_ABSD) $(BIN_LINUX):
	mkdir -p $@
.PHONY: all
