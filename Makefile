HDR = $(wildcard *.h)
SRC = $(wildcard *.c)
OBJ = $(SRC:.c=.o)
EXE = $(subst .o,,$(OBJ))

SUBDIR = lib

LINTER    = cppcheck
LINTFLAGS = --enable=style -j 4

REQ = openssl
LIB = lib/libktls.a

CFLAGS  += -Wall -Werror -g -O2 $(shell pkg-config --cflags $(REQ)) -I./include
LDFLAGS += $(shell pkg-config --libs $(REQ))

.PHONY: all clean lint $(SUBDIR)


all: $(SUBDIR) $(EXE) $(OBJ)

%:%.o
	$(CC) -o $@ $< $(LIB) $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(SUBDIR):
	$(MAKE) -C $@ $(MAKECMDGOALS)

lint: $(SRC) $(HDR) $(SUBDIR)
	$(LINTER) $(LINTFLAGS) $^

clean: $(SUBDIR)
	rm -rf $(OBJ) $(EXE)
