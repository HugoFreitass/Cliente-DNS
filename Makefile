CC := gcc

CFLAGS := -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -Iinclude

TARGET := meu_cliente
TEST_TARGET := tests/test_dns_client_timeout

SOURCES := \
    app/main.c \
    src/cli.c \
    src/dns_client.c

OBJECTS := $(SOURCES:.c=.o)

.PHONY: all test clean

all: $(TARGET)

test: $(TEST_TARGET)
	./$(TEST_TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

app/%.o: app/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_TARGET): tests/test_dns_client.c src/dns_client.c include/dns_client.h
	$(CC) $(CFLAGS) tests/test_dns_client.c src/dns_client.c -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_TARGET)