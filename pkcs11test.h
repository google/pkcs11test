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

#endif  // PKCS11TEST_H
