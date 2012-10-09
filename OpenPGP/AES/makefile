# makefile for BlackLight

aes.o:		aes.c
		gcc -c aes.c -o aes.o

aes.dylib:	aes.o
		gcc -dynamiclib -Wall -o aes.dylib aes.o

