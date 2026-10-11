CC      ?= gcc
SRC     := src/main.c src/server.c src/load_balancer.c src/health_check.c \
           src/buffer_pool.c src/config.c
BIN     := revproxy
COMMON  := -std=c11 -D_GNU_SOURCE -Wall -Wextra -Werror -pedantic -Iinclude -pthread

.PHONY: all debug release valgrind-build clean

all: debug

debug:
	$(CC) $(COMMON) -O0 -g -fsanitize=address,undefined -o $(BIN) $(SRC)

release:
	$(CC) $(COMMON) -O3 -DNDEBUG -o $(BIN) $(SRC)

# no sanitizers. asan and valgrind do not share a process.
valgrind-build:
	$(CC) $(COMMON) -O0 -g -o $(BIN) $(SRC)

clean:
	rm -f $(BIN)
