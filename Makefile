SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(subst .o,,$(OBJ))

REQ = openssl

CFLAGS += -Wall -g
LDFLAGS = $(shell pkg-config --libs $(REQ))

.PHONY: all clean

all: $(EXE)

clean:
	rm -rf $(OBJ) $(EXE)
