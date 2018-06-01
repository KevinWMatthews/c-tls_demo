### List all executables here
EXEC = test_sslserver test_sslclient ssl_client

### List source and object files for all executables here
test_sslserver_SRC = test_sslserver.c
test_sslserver_OBJ = $(call c_to_o,$(test_sslserver_SRC))

test_sslclient_SRC = test_sslclient.c
test_sslclient_OBJ = $(call c_to_o,$(test_sslclient_SRC))

ssl_client_SRC = ssl_client.c
ssl_client_OBJ = $(call c_to_o,$(ssl_client_SRC))

### Directory structure
SRC_DIR = src
OBJ_DIR = obj
BIN_DIR = bin


### Compiler and linker flags (currently global)
CFLAGS = -Wall
LDFLAGS = -lssl -lcrypto

### Helper functions. Must be listed before targets.
c_to_o = $(patsubst %.c,%.o,$1) 		# Convert list of .c files to list of .o files

### Add rules for each executable
test_sslserver: $(test_sslserver_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_DIR)/$^ -o $(BIN_DIR)/$@ $(LDFLAGS)

test_sslclient: $(test_sslclient_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_DIR)/$^ -o $(BIN_DIR)/$@ $(LDFLAGS)

ssl_client: $(ssl_client_OBJ)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $(OBJ_DIR)/$^ -o $(BIN_DIR)/$@ $(LDFLAGS)

### Rules below should not need to be changed
.PHONY: all clean
.DEFAULT_GOAL = all

all: $(EXEC)

# Target does not contain OBJ_DIR prefix.
# Source code is found in SRC_DIR; add prefix.
%.o: src/%.c
	@mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c $< -o $(OBJ_DIR)/$@ $(LDFLAGS)

clean:
	rm -rf $(OBJ_DIR) $(BIN_DIR)


### Documentation
# $@ 	target
# $^	all dependencies, space-separated list
# $<	first dependency
# %		wildcard
