CC := gcc

CFLAGS := -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -Iinclude

TARGET := meu_cliente

TEST_DNS_NAME := test_dns_name

SOURCES := \
    app/main.c \
    src/cli.c

OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean test test_dns_name

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(TEST_DNS_NAME): tests/test_dns_name.c src/dns_name.c
	$(CC) $(CFLAGS) $^ -o $@

test_dns_name: $(TEST_DNS_NAME)
	./$(TEST_DNS_NAME)

test: test_dns_name

clean:
	rm -f $(OBJECTS) $(TARGET) $(TEST_DNS_NAME) $(TEST_DNS_NAME).exe