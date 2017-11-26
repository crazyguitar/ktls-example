SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
LIB = libktls.a 

CFLAGS = -Wall -Werror -g -O2 -I../include

.PHONY: all clean lint

all: $(LIB)

$(LIB): $(OBJ)
	ar rcs $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $^

lint:

clean:
	rm -rf $(OBJ) $(LIB)
