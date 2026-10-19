# zlib 1.3.2: the library sources plus test/example.c and test/minigzip.c.
# ./configure's results on the command line (DEMAND.md 4): HAVE_UNISTD_H and
# HAVE_STDARG_H (zconf.h tests them with -0, so no edit), HAVE_HIDDEN; no
# _LARGEFILE64_SOURCE. The library objects are compiled once for both products.
ZLIB_A := $(UP)/zlib/absd/zlib-1.3.2
ZLIB_L := $(UP)/zlib/linux/zlib-1.3.2
ZLIB_FLAGS := -O2 -DHAVE_UNISTD_H=1 -DHAVE_STDARG_H=1 -DHAVE_HIDDEN
ZLIB_NAMES := adler32 compress crc32 deflate gzclose gzlib gzread gzwrite infback \
  inffast inflate inftrees trees uncompr zutil
ZLIB_OBJS := $(patsubst %,$(OBJ)/absd/zlib/%.o,$(ZLIB_NAMES))
ZLIB_LSRC := $(patsubst %,$(ZLIB_L)/%.c,$(ZLIB_NAMES))
$(OBJ)/absd/zlib/%.o: $(ZLIB_A)/%.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(ZLIB_FLAGS) -I$(ZLIB_A) -o $@ $<
$(OBJ)/absd/zlib/%.o: $(ZLIB_A)/test/%.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(ZLIB_FLAGS) -I$(ZLIB_A) -o $@ $<
$(BIN_ABSD)/example $(BIN_ABSD)/minigzip: $(BIN_ABSD)/%: $(ZLIB_OBJS) $(OBJ)/absd/zlib/%.o $(POSIX_A)
	$(CC_ABSD) -o $@ $(ZLIB_OBJS) $(OBJ)/absd/zlib/$*.o $(POSIX_A)
	printf '%s\n' $(ZLIB_OBJS) $(OBJ)/absd/zlib/$*.o > $(OBJ)/absd/$*.objs
$(BIN_LINUX)/example $(BIN_LINUX)/minigzip: $(BIN_LINUX)/%: $(ZLIB_LSRC) $(ZLIB_L)/test/%.c
	$(CC_LINUX) $(PREFIX_MAP) $(ZLIB_FLAGS) -I$(ZLIB_L) -o $@ $^
PRODUCTS += example
PRODUCTS += minigzip
