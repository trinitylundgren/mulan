# @file - Makfile
# @author - Trinity Lundgren <lundgret@oregonstate.edu>
# @description - Makefile for mulan, a CLI ping program for Linux.

# Project name
project = mulan

# Compiler
CXX = gcc

# Source files
sources = mulan.c utils.c

# Create objects from source files
objects = $(sources:.c=.o)

# Output executable
EXE = $(project)

# Compiler flags
CFLAGS = -Wall -pedantic -std=gnu11

#Valgrind options
VOPT = --tool=memcheck --leak-check=full --show-leak-kinds=all --track-origins=yes

# Phony targets
.PHONY: default debug clean zip

# Default behavior: clean, compile, pass through valgrind
default: clean $(EXE) #debug # Debug is toggled off for submission

# Debug: pass to valgrind to check for memory leaks
debug: $(EXE)
	valgrind $(VOPT) ./$(EXE)

# '$@' refers to tag, '$^' to dependency
$(EXE) : $(objects)
	$(CXX) $(CFLAGS) $^ -o $@

# Create .o files from corresponding .cpp files
%.o: %.c
	$(CXX) $(CFLAGS) -c $^

# Create a zip archive of the project files for submission
zip:
	zip -r $(project)_Lundgren_Trinity.zip img *.c *.h Makefile *.md

clean:
	rm -f *.o *.zip $(EXE)
