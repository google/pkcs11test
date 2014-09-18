SLOT_ID ?= 0
all: pkcs11test
test_opencryptoki: pkcs11test
	OPENCRYPTOKI_DEBUG_FILE=opencryptoki.out ./pkcs11test -m libopencryptoki.so -l /usr/lib/x86_64-linux-gnu/opencryptoki -s $(SLOT_ID)
test_chaps: pkcs11test
	./pkcs11test -m libchaps.so -l /usr/lib -s $(SLOT_ID)

# Run the specific tests that dump token contents
dump_opencryptoki: pkcs11test
	OPENCRYPTOKI_DEBUG_FILE=opencryptoki.out ./pkcs11test -m libopencryptoki.so -l /usr/lib/x86_64-linux-gnu/opencryptoki -v --gtest_filter=*.Enumerate* -s 1

GTEST_DIR=gtest-1.6.0
GTEST_INC=-isystem $(GTEST_DIR)/include
CXXFLAGS+=-Ithird_party/pkcs11  $(GTEST_INC) -g -std=c++0x -Wall
OBJECTS=pkcs11test.o pkcs11-describe.o globals.o init.o slot.o session.o object.o login.o rng.o tookan.o keypair.o cipher.o digest.o

pkcs11test: $(OBJECTS) libgtest.a
	$(CXX) -g $(GTEST_INCS) -o $@ $(OBJECTS) -ldl libgtest.a -lpthread

gtest-all.o:
	$(CXX) $(CXXFLAGS) -I$(GTEST_DIR) -c $(GTEST_DIR)/src/gtest-all.cc
libgtest.a: gtest-all.o
	$(AR) -rv libgtest.a gtest-all.o

clean:
	rm -rf pkcs11test $(OBJECTS) gtest-all.o libgtest.a opencryptoki.out
