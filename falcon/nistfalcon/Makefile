# This Makefile compiles the implementation in this directory along with
# the known answer tests generator located in the
# KAT/generator/ directory. The output is an executable program
# in the build/ subdirectory, whose name starts with 'kat', followed by
# the implementation name (e.g. 'kat512int' for the 'falcon512int'
# implementation). This program, when executed, generates the .req and
# .rsp files in the expected NIST format.

.POSIX:

CC = gcc
CFLAGS = -W -Wall -O2 -DALGNAME=falcon512int
LD = gcc
LDFLAGS = 
LIBS = 

OBJ1 = build/codec.o build/common.o build/fft.o build/fpr.o build/keygen.o build/nist.o build/nist16.o build/epervier16.o build/rng.o build/shake.o build/sign.o build/vrfy.o

OBJ2 = build/PQCgenKAT_sign.o build/katrng.o
OBJ3 = build/PQCgenKAT_sign_zknox.o build/katrng.o
OBJ4 = build/PQCgenKAT_sign_epervier_zknox.o build/katrng.o
OBJ5 = build/PQCgenKAT_hashtopoint.o build/katrng.o
OBJ6 = build/PQCgenKAT_falconcore.o build/katrng.o

HEAD1 = src/api.h src/fpr.h src/inner.h
HEAD2 = src/api.h src/katrng.h

all: build build/kat512int build/kat512int_hashtopoint build/kat512int_falconcore build/kat512int_zknox build/kat512int_epervier_zknox

build:
	-mkdir build

clean:
	-rm -f build/kat512int build/kat512int_zknox build/kat512int_epervier_zknox build/kat512int_hashtopoint $(OBJ1) $(OBJ2) $(OBJ3) $(OBJ4) $(OBJ5)
	find . -name '*.rsp' -delete
	find . -name '*.req' -delete 
	
build/kat512int: $(OBJ1) $(OBJ2)
	$(LD) $(LDFLAGS) -o build/kat512int $(OBJ1) $(OBJ2) $(LIBS)

build/kat512int_zknox: $(OBJ1) $(OBJ3)
	$(LD) $(LDFLAGS) -o build/kat512int_zknox $(OBJ1) $(OBJ3) $(LIBS)

build/kat512int_epervier_zknox: $(OBJ1) $(OBJ4)
	$(LD) $(LDFLAGS) -o build/kat512int_epervier_zknox $(OBJ1) $(OBJ4) $(LIBS)

build/kat512int_hashtopoint: $(OBJ1) $(OBJ5)
	$(LD) $(LDFLAGS) -o build/kat512int_hashtopoint $(OBJ1) $(OBJ5) $(LIBS)

build/kat512int_falconcore: $(OBJ1) $(OBJ6)
	$(LD) $(LDFLAGS) -o build/kat512int_falconcore $(OBJ1) $(OBJ6) $(LIBS)

build/codec.o: src/codec.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/codec.o src/codec.c

build/common.o: src/common.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/common.o src/common.c

build/fft.o: src/fft.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/fft.o src/fft.c

build/fpr.o: src/fpr.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/fpr.o src/fpr.c

build/keygen.o: src/keygen.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/keygen.o src/keygen.c

build/nist.o: src/nist.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/nist.o src/nist.c

build/nist16.o: src/nist16.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/nist16.o src/nist16.c

build/epervier16.o: src/epervier16.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/epervier16.o src/epervier16.c

build/rng.o: src/rng.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/rng.o src/rng.c

build/shake.o: src/shake.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/shake.o src/shake.c

build/sign.o: src/sign.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/sign.o src/sign.c

build/vrfy.o: src/vrfy.c $(HEAD1)
	$(CC) $(CFLAGS) -c -o build/vrfy.o src/vrfy.c

build/PQCgenKAT_sign.o: KAT/PQCgenKAT_sign.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -DALGNAME=falcon512int -c -o build/PQCgenKAT_sign.o KAT/PQCgenKAT_sign.c

build/PQCgenKAT_sign_zknox.o: KAT/PQCgenKAT_sign_zknox.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -DALGNAME=falcon512int -c -o build/PQCgenKAT_sign_zknox.o KAT/PQCgenKAT_sign_zknox.c
	
build/PQCgenKAT_sign_epervier_zknox.o: KAT/PQCgenKAT_sign_epervier_zknox.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -DALGNAME=falcon512int -c -o build/PQCgenKAT_sign_epervier_zknox.o KAT/PQCgenKAT_sign_epervier_zknox.c
	
build/PQCgenKAT_hashtopoint.o: KAT/PQCgenKAT_hashtopoint.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -DALGNAME=falcon512int -c -o build/PQCgenKAT_hashtopoint.o KAT/PQCgenKAT_hashtopoint.c

build/PQCgenKAT_falconcore.o: KAT/PQCgenKAT_falconcore.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -DALGNAME=falcon512int -c -o build/PQCgenKAT_falconcore.o KAT/PQCgenKAT_falconcore.c

build/katrng.o: src/katrng.c $(HEAD2)
	$(CC) $(CFLAGS) -I src/ -c -o build/katrng.o src/katrng.c
