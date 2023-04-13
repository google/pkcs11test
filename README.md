pkcs11Test: A PKCS#11 Test Suite
================================

**Warning: Do not run this test suite against a PKCS#11 token that contains real data; some of the tests may erase or
  permanently lock the token.**

This repository holds a test suite for, and is therefore derived from, the
[RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm).

The test suite exercises v2.2 of the PKCS#11 interface, and covers:

- library management (`init.cc`)
- slot and token management (`slot.cc`)
- session management (`session.cc`, `login.cc`)
- object management (`object.cc`)
- key management (`key.cc`)
- symmetric encryption and decryption (`cipher.cc`)
- asymmetric encryption and decryption (`cipher.cc`)
- signing and verification (`sign.cc`, `hmac.cc`)
- message digesting (`digest.cc`)
- dual-function mechanisms (`dual.cc`)


To build the test program on Linux, just run `make`.  To run the tests against
common Linux PKCS#11 implementations:

 - Run `make test_opencryptoki` to test against an
   [OpenCryptoKi](http://sourceforge.net/projects/opencryptoki/) [installation](https://packages.debian.org/wheezy/admin/opencryptoki).

This is NOT an official Google product.

Additional make options
 - PKCS11_LONGTYPE=32 - set CK_LONG/CK_ULONG size to int32_t/uint32_t. Normally set to long int, which is machine/compiler dependent.
 - STRICT_P11=1 - set structures to packed, which tests against fully compliant PKCS11 implementations.
   example:
            make PKCS11_LONGTYPE=32 STRICT_P11=1


Test Options
------------

The test program requires the following command-line parameters to be set:

 - `-m libname`: Provide the name of the PKCS#11 library to test.
 - `-l libpath`: Provide the path holding the PKCS#11 library.

There are also several optional command-line parameters:

 - `-s slotid`: Provide the slot ID that will be used for the tests
 - `-v`: Generate verbose output.
 - `-u pwd`: Provide the user PIN/password.
 - `-o pwd`: Provide the security officer PIN/password.
 - `-w cnm`: Name of cipher to use for keys being wrapped in key-wrapping tests. One of {
              3DES-CBC, 3DES-ECB, AES-CBC
            , AES-ECB, ARIA-CBC, ARIA-CBC-PAD
            , ARIA-ECB, CAMELLIA-CBC, CAMELLIA-CBC-PAD
            , CAMELLIA-ECB, DES-CBC, DES-ECB
            , IDEA-CBC, IDEA-ECB }
 - `-I`: Perform token initialization tests. **This will wipe the contents of the PKCS#11 token**

The test program uses [Google Test](https://code.google.com/p/googletest/), and
the
[Google Test command line options](https://code.google.com/p/googletest/wiki/V1_6_AdvancedGuide#Running_Test_Programs:_Advanced_Options)
are also available.  In particular, `--gtest_filter=<filter>` can be used to run a subset of the tests.
