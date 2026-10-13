CC := gcc

CFLAGS := -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -Iinclude

TARGET := meu_cliente
TEST_TARGET := tests/test_dns_client_timeout
TEST_TARGETS := tests/test_dns_packet tests/test_dns_mx

SOURCES := \
    app/main.c \
    src/cli.c \
    src/dns_client.c \
    src/dns_retry.c \
    src/dns_packet.c \
    src/dns_name.c \
    src/mx_lookup.c

OBJECTS := $(SOURCES:.c=.o)

.PHONY: all test clean

all: $(TARGET)

test: $(TEST_TARGET) $(TEST_TARGETS)
	./$(TEST_TARGET)
	./tests/test_dns_packet
	./tests/test_dns_mx

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

app/%.o: app/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_TARGET): tests/test_dns_client.c src/dns_client.c include/dns_client.h
	$(CC) $(CFLAGS) tests/test_dns_client.c src/dns_client.c -o $@

tests/test_dns_packet: tests/test_dns_packet.c src/dns_packet.c src/dns_name.c
	$(CC) $(CFLAGS) $^ -o $@

tests/test_dns_mx: tests/test_dns_mx.c src/mx_lookup.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_TARGET) $(TEST_TARGETS)