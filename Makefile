CC      ?= gcc
CFLAGS  ?= -O2 -std=c11 -Wall -Wextra -D_GNU_SOURCE -pthread
LDFLAGS ?= -static
OBJ      = src/labsentry.o src/sha256.o vendor/sqlite3.o
BIN      = labsentry

# SQLite needs threads + dl for static link
SQLITE_DEFINES = -DSQLITE_THREADSAFE=1 -DSQLITE_OMIT_LOAD_EXTENSION=1

.PHONY: all clean test install

all: $(BIN)

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/
	install -d $(DESTDIR)$(PREFIX)/share/labsentry/tools
	install -m 0644 tools/report.py $(DESTDIR)$(PREFIX)/share/labsentry/tools/

vendor/sqlite3.o: vendor/sqlite3.c
	$(CC) $(CFLAGS) $(SQLITE_DEFINES) -c $< -o $@

src/sha256.o: src/sha256.c
	$(CC) $(CFLAGS) -c $< -o $@

src/labsentry.o: src/labsentry.c src/sha256.h vendor/sqlite3.h
	$(CC) $(CFLAGS) -Ivendor -c $< -o $@

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJ) -lpthread -ldl -o $@

clean:
	rm -f $(OBJ) $(BIN)

# smoke test
test: $(BIN)
	./$(BIN) gpu
	./$(BIN) ports
	@mkdir -p /tmp/ls-test
	@echo "hello model" > /tmp/ls-test/model.gguf
	./$(BIN) scan --roots /tmp/ls-test --db /tmp/ls-test/audit.db --json /tmp/ls-test/r.json
	./$(BIN) img --in /tmp/ls-test --out /tmp/ls-test/out || true
	PREFIX=/tmp/ls-test ./$(BIN) report --json /tmp/ls-test/r.json | head -5
