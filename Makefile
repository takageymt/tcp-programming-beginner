TARGET=tcp
SRCS=$(wildcard *.c)
OBJS=$(SRCS:.c=.o)

CFLAGS=-Wall -g
LDLIBS=-lpthread

.SUFFIXES: .c .o
.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDLIBS) -o $@ $^

.c.o: $<
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f $(TARGET) $(OBJS)
