test: pkcs11test

OBJECTS=pkcs11test.o

pkcs11test: $(OBJECTS)
	$(CXX) -g -o $@ $< -I ../chaps/pkcs11 -ldl

clean:
	rm -rf pkcs11test $(OBJECTS)