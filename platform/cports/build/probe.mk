# The adapter's guest probe. Variables from cports/build/Makefile: CC_ABSD, CC_LINUX, OBJ, BIN_ABSD, BIN_LINUX, POSIX_A, ROOT, PREFIX_MAP.
PROBE_SRC := $(ROOT)/c/posix/tests/guest/posixprobe.c
$(BIN_ABSD)/posixprobe: $(PROBE_SRC) $(POSIX_A)
	$(CC_ABSD) -c $(PREFIX_MAP) -o $(OBJ)/absd/posixprobe.o $(PROBE_SRC)
	$(CC_ABSD) -o $@ $(OBJ)/absd/posixprobe.o $(POSIX_A)
$(BIN_LINUX)/posixprobe: $(PROBE_SRC)
	$(CC_LINUX) $(PREFIX_MAP) -std=gnu11 -O2 -o $@ $(PROBE_SRC)
PRODUCTS += posixprobe
