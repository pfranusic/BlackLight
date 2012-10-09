# makefile for BlackLight RNG

random.o:		random.c
			gcc -c random.c -o random.o

random.dylib:		random.o
			gcc -dynamiclib -Wall -o random.dylib random.o

