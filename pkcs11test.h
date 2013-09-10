#ifndef PKCS11TEST_H
#define PKCS11TEST_H

// Master header for all PKCS#11 test code.

// Set up the environment for PKCS#11
#include "pkcs11-env.h"
// Include the official PKCS#11 header file.
#include <pkcs11.h>
// Test-wide global variables (specifically g_fns)
#include "globals.h"
// Utilities to convert PKCS#11 types to strings.
#include "pkcs11-describe.h"
// gTest header
#include "gtest/gtest.h"

// Additional macro for checking the return value of a PKCS#11 function.
inline ::testing::AssertionResult IsCKR_OK(CK_RV rv) {
  if (rv == CKR_OK) {
    return testing::AssertionSuccess();
  } else {
    return testing::AssertionFailure() << rv_name(rv);
  }
}
#define EXPECT_CKR_OK(val) EXPECT_TRUE(IsCKR_OK(val))

// Test case that handles Initialize/Finalize
class PKCS11Test : public ::testing::Test {
 protected:
  virtual void SetUp() {
    // Null argument => only planning to use PKCS#11 from single thread.
    EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  }
  virtual void TearDown() {
    EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  }
};

// Test case that handles session setup/teardown
class ReadOnlySessionTest : public PKCS11Test {
 protected:
  virtual void SetUp() {
    CK_FLAGS flags = CKF_SERIAL_SESSION;
    EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session_));
  }
  virtual void TearDown() {
    EXPECT_CKR_OK(g_fns->C_CloseSession(session_));
  }
  CK_SESSION_HANDLE session_;
};

#endif  // PKCS11TEST_H
