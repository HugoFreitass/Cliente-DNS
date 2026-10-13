CC := gcc

CFLAGS := -std=c11 \
          -Wall \
          -Wextra \
          -Wpedantic \
          -Iinclude

TARGET := meu_cliente

SOURCES := \
    app/main.c \
    src/cli.c \
    src/dns_client.c

OBJECTS := $(SOURCES:.c=.o)

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) -o $@

app/%.o: app/%.c
	$(CC) $(CFLAGS) -c $< -o $@

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)