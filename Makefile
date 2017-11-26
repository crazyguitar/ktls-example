SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(subst .o,,$(OBJ))

REQ = openssl

CFLAGS  += -Wall -Werror -g -O2 $(shell pkg-config --cflags $(REQ))
LDFLAGS += $(shell pkg-config --libs $(REQ))

.PHONY: all clean

all: $(EXE) $(OBJ)

%:%.o
	$(CC) $< -o $@ $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(OBJ) $(EXE)
