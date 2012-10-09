# makefile for sha256.dylib

sha256.o:	sha256.c
		gcc -c sha256.c -o sha256.o

sha256.dylib:	sha256.o
		gcc -dynamiclib -Wall -o sha256.dylib sha256.o

