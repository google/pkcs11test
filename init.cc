#include "pkcs11test.h"

using namespace std;  // So sue me

// Explicitly test Initialize/Finalize.
TEST(Init, Simple) {
  EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, UnexpectedFinalize) {
  EXPECT_EQ(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgsBadReserved) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.pReserved = (void*)1;
  EXPECT_EQ(CKR_ARGUMENTS_BAD, g_fns->C_Initialize(&init_args));
}

TEST(Init, InitArgsNoNewThreads) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
  CK_RV rv = g_fns->C_Initialize(&init_args);
  if (rv == CKR_OK) {
    cout << "Library can cope without creating OS threads" << endl;
    EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  } else {
    cout << "Library needs to be able to create OS threads" << endl;
    EXPECT_EQ(CKR_NEED_TO_CREATE_THREADS, rv);
  }
}

TEST(Init, InitArgsNoLock) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  EXPECT_CKR_OK(g_fns->C_Initialize(&init_args));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgsInternalLocks) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  // Expect the library to use OS threading primitives
  EXPECT_CKR_OK(g_fns->C_Initialize(&init_args));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

// TODO(drysdale): add the other two cases (function pointers supplied, flag set+not-set)

// From here on, wrap Initialize/Finalize in a fixture.
TEST_F(PKCS11Test, InitNestedFail) {
  EXPECT_EQ(CKR_CRYPTOKI_ALREADY_INITIALIZED, g_fns->C_Initialize(NULL_PTR));
}

TEST_F(PKCS11Test, GetInfo) {
  CK_INFO info = {0};
  EXPECT_CKR_OK(g_fns->C_GetInfo(&info));
  cout << info_description(&info) << endl;
  EXPECT_LE(2, info.cryptokiVersion.major);
}

TEST_F(PKCS11Test, FailedTermination) {
  EXPECT_EQ(CKR_ARGUMENTS_BAD, g_fns->C_Finalize((void *)1));
}
