pkcs11Test: A PKCS#11 Test Suite
================================

**Warning: Do not run this test suite against a PKCS#11 token that contains real data; some of the tests may erase or
  permanently lock the token.**

This repository holds a test suite for, and is therefore derived from, the
[RSA Security Inc. PKCS #11 Cryptographic Token Interface (Cryptoki)](http://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-11-cryptographic-token-interface-standard.htm).

To build the test program on Linux, just run `make`.  To run the tests against
common Linux PKCS#11 implementations:

 - Run `make test_chaps` to test against a
   [Chaps](https://github.com/google/chaps-linux) installation.
 - Run `make test_opencryptoki` to test against an
   [OpenCryptoKi](http://sourceforge.net/projects/opencryptoki/) [installation](https://packages.debian.org/wheezy/admin/opencryptoki).

This is NOT an official Google product.


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
 - `-I`: Perform token initialization tests. **This will wipe the contents of the PKCS#11 token**

The test program uses [Google Test](https://code.google.com/p/googletest/), and
the
[Google Test command line options](https://code.google.com/p/googletest/wiki/V1_6_AdvancedGuide#Running_Test_Programs:_Advanced_Options)
are also available.  In particular, `--gtest_filter=<filter>` can be used to run a subset of the tests.
