CC = gcc
CFLAGS = -Wall -Wextra -O2 -std=c99
TARGET = main
SOURCES = main.c notification_client.c
HEADERS = notification_client.h

all: $(TARGET)

$(TARGET): $(SOURCES) $(HEADERS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCES)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

.PHONY: all clean run
