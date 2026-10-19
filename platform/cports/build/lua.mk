# Lua 5.4.9, upstream `make generic` (src/Makefile: CC gcc -std=gnu99,
# CFLAGS -O2 -Wall -Wextra -DLUA_COMPAT_5_3): no LUA_USE_POSIX, no dlopen,
# no readline. Every src/*.c except luac.c. Linux adds -lm; ABSD's libm is the kit's.
LUA_A := $(UP)/lua/absd/lua-5.4.9/src
LUA_L := $(UP)/lua/linux/lua-5.4.9/src
LUA_FLAGS := -std=gnu99 -O2 -Wall -Wextra -DLUA_COMPAT_5_3
LUA_NAMES := lapi lauxlib lbaselib lcode lcorolib lctype ldblib ldebug ldo ldump \
  lfunc lgc linit liolib llex lmathlib lmem loadlib lobject lopcodes loslib lparser \
  lstate lstring lstrlib ltable ltablib ltm lua lundump lutf8lib lvm lzio
LUA_OBJS := $(patsubst %,$(OBJ)/absd/lua/%.o,$(LUA_NAMES))
$(OBJ)/absd/lua/%.o: $(LUA_A)/%.c
	@mkdir -p $(dir $@)
	$(CC_ABSD) -c $(PREFIX_MAP) $(LUA_FLAGS) -o $@ $<
$(BIN_ABSD)/lua: $(LUA_OBJS) $(POSIX_A)
	$(CC_ABSD) -o $@ $(LUA_OBJS) $(POSIX_A)
	printf '%s\n' $(LUA_OBJS) > $(OBJ)/absd/lua.objs
$(BIN_LINUX)/lua: $(patsubst %,$(LUA_L)/%.c,$(LUA_NAMES))
	$(CC_LINUX) $(PREFIX_MAP) $(LUA_FLAGS) -o $@ $^ -lm
PRODUCTS += lua
