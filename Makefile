CC = gcc
CFLAGS = -Wall -Wextra -g
LDFLAGS = -lpcap

TARGET = cshark
SOURCES = cshark.c packet_parser.c
OBJECTS = $(SOURCES:.c=.o)
HEADERS = cshark.h packet_parser.h

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LDFLAGS)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(TARGET)

.PHONY: all clean
