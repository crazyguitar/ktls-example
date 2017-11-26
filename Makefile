HDR = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(subst .o,,$(OBJ))

LINTER    = cppcheck
LINTFLAGS = --enable=style -j 4

REQ = openssl

CFLAGS  += -Wall -Werror -g -O2 $(shell pkg-config --cflags $(REQ))
LDFLAGS += $(shell pkg-config --libs $(REQ))

.PHONY: all clean lint

all: $(EXE) $(OBJ)

%:%.o
	$(CC) $< -o $@ $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

lint: $(SRC) $(HDR)
	$(LINTER) $(LINTFLAGS) $^

clean:
	rm -rf $(OBJ) $(EXE)
