CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -Wall -Wextra -Wpedantic -Wshadow
LDLIBS  += -lpthread

SRC = src/md5.c src/digest.c src/sipmini.c src/registrar.c src/loadgen.c

all: ims-regtest

ims-regtest: $(SRC) src/main.c src/*.h
	$(CC) $(CFLAGS) -o $@ $(SRC) src/main.c $(LDLIBS)

test_crypto: src/md5.c src/digest.c tests/test_crypto.c src/*.h
	$(CC) $(CFLAGS) -o $@ src/md5.c src/digest.c tests/test_crypto.c

test: test_crypto ims-regtest
	./test_crypto
	./ims-regtest --ues 2000 --rate 2000
	./ims-regtest --ues 1000 --rate 1000 --loss 10 --t1 50
	! ./ims-regtest --ues 200 --rate 1000 --wrong-password > wrong.out
	grep -q "forbidden 200" wrong.out && rm -f wrong.out

asan: CFLAGS += -fsanitize=address,undefined -fno-omit-frame-pointer
asan: clean test

tsan: CFLAGS += -fsanitize=thread
tsan: clean test

clean:
	rm -f ims-regtest test_crypto wrong.out

.PHONY: all test asan tsan clean
