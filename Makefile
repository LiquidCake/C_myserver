IDIR=include
LDIR=lib
ODIR=obj
SRCDIR=src


DEPS=myserver.h response_handler.h mylib.h
OBJ=myserver.o response_handler.o mylib.o

CC=gcc
CFLAGS=-g -I $(IDIR)
LIBS=-lm

#patsubst {pattern},{replacement},{inputstr}
DEPS_FILES=$(patsubst %,$(IDIR)/%,$(DEPS))
OBJ_FILES=$(patsubst %,$(ODIR)/%,$(OBJ))

#compiles each found .c file. And next run created .o file will depend on both source .c file and all DEPS headers. This somehow expands into copy per each .c file found
$(ODIR)/%.o: $(SRCDIR)/%.c $(DEPS_FILES)
	$(CC) -c -o $@ $< $(CFLAGS)

OUT_1=myserver
$(OUT_1): $(OBJ_FILES)
	$(CC) -o $@ $^ $(CFLAGS) $(LIBS)	


.PHONY: clean
clean:
	rm $(ODIR)/*.* || true
	rm $(OUT_1) || true
