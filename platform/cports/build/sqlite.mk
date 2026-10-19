# SQLite 3.54.0: the amalgamation with shell.c (sqlite3) and with
# sqlite-src's test/speedtest1.c (speedtest1). The option set of SQLITE-VFS.md 7
# (no WAL, no mmap, no locking styles, no threads, no extensions, temporary
# storage in memory), no HAVE_* on either side (DEMAND.md 4), _GNU_SOURCE for
# Picolibc's XSI declarations. ABSD compiles shell.c through shell-absd.c,
# which includes sys/termios.h first (struct winsize; absd-cc has no -include).
# Linux adds -lm.
SQL_A := $(UP)/sqlite-amalgamation/absd/sqlite-amalgamation-3540000
SQL_L := $(UP)/sqlite-amalgamation/linux/sqlite-amalgamation-3540000
SQLT_A := $(UP)/sqlite-src/absd/sqlite-src-3540000/test
SQLT_L := $(UP)/sqlite-src/linux/sqlite-src-3540000/test
SQL_FLAGS := -O2 -DSQLITE_OS_UNIX=1 -DSQLITE_THREADSAFE=0 -DSQLITE_OMIT_LOAD_EXTENSION \
  -DSQLITE_ENABLE_LOCKING_STYLE=0 -DSQLITE_OMIT_WAL -DSQLITE_MAX_MMAP_SIZE=0 \
  -DSQLITE_TEMP_STORE=3 -D_GNU_SOURCE
SQL_O := $(OBJ)/absd/sqlite
$(SQL_O)/sqlite3.o: $(SQL_A)/sqlite3.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(SQL_FLAGS) -I$(SQL_A) -o $@ $<
$(SQL_O)/shell.o: $(ROOT)/cports/build/shell-absd.c $(SQL_A)/shell.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(SQL_FLAGS) -I$(SQL_A) -o $@ $<
$(SQL_O)/speedtest1.o: $(SQLT_A)/speedtest1.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(SQL_FLAGS) -I$(SQL_A) -o $@ $<
$(BIN_ABSD)/sqlite3: $(SQL_O)/sqlite3.o $(SQL_O)/shell.o $(POSIX_A)
	$(CC_ABSD) -o $@ $(SQL_O)/sqlite3.o $(SQL_O)/shell.o $(POSIX_A)
	printf '%s\n' $(SQL_O)/sqlite3.o $(SQL_O)/shell.o > $(OBJ)/absd/sqlite3.objs
$(BIN_ABSD)/speedtest1: $(SQL_O)/sqlite3.o $(SQL_O)/speedtest1.o $(POSIX_A)
	$(CC_ABSD) -o $@ $(SQL_O)/sqlite3.o $(SQL_O)/speedtest1.o $(POSIX_A)
	printf '%s\n' $(SQL_O)/sqlite3.o $(SQL_O)/speedtest1.o > $(OBJ)/absd/speedtest1.objs
# Linux: the amalgamation compiled once, linked into both products.
$(OBJ)/linux/sqlite3.o: $(SQL_L)/sqlite3.c | $(OBJ)/linux
	$(CC_LINUX) $(PREFIX_MAP) -c $(SQL_FLAGS) -I$(SQL_L) -o $@ $<
$(BIN_LINUX)/sqlite3: $(OBJ)/linux/sqlite3.o $(SQL_L)/shell.c
	$(CC_LINUX) $(PREFIX_MAP) $(SQL_FLAGS) -I$(SQL_L) -o $@ $^ -lm
$(BIN_LINUX)/speedtest1: $(OBJ)/linux/sqlite3.o $(SQLT_L)/speedtest1.c
	$(CC_LINUX) $(PREFIX_MAP) $(SQL_FLAGS) -I$(SQL_L) -o $@ $^ -lm
PRODUCTS += sqlite3
PRODUCTS += speedtest1
