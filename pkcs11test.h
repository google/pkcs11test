/* -*- c++ -*- */
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

#include <iostream>
#include <memory>

// Value to use for invalid slot IDs.
#define INVALID_SLOT_ID 88888
// Value to use for invalid session handles.
#define INVALID_SESSION_HANDLE 99999

// Deleter for std::unique_ptr that handles C's malloc'ed memory.
struct freer {
  void operator()(void* p) { free(p); }
};

// Additional macros for checking the return value of a PKCS#11 function.
struct CK_RV_ {
  CK_RV_(CK_RV rv) : rv_(rv) {}
  CK_RV rv_;
  bool operator==(const CK_RV_& other) const { return rv_ == other.rv_; }
};
inline std::ostream& operator<<(std::ostream& os, const CK_RV_& wrv) {
  os << rv_name(wrv.rv_);
  return os;
}
#define EXPECT_CKR(expected, actual) EXPECT_EQ(CK_RV_(expected), CK_RV_(actual))
#define EXPECT_CKR_OK(val) EXPECT_CKR(CKR_OK, (val))

// Test case that handles Initialize/Finalize
class PKCS11Test : public ::testing::Test {
 public:
  PKCS11Test() {
    // Null argument => only planning to use PKCS#11 from single thread.
    EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  }
  virtual ~PKCS11Test() {
    EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  }
};

// Test cases that handle session setup/teardown
class SessionTest : public PKCS11Test {
 public:
  SessionTest() {
    CK_SLOT_INFO slot_info;
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(g_slot_id, &slot_info));
    if (!(slot_info.flags & CKF_TOKEN_PRESENT)) {
      std::cerr << "Need to specify a slot ID that has a token present" << std::endl;
      exit(1);
    }
  }
  virtual ~SessionTest() {
    EXPECT_CKR_OK(g_fns->C_CloseSession(session_));
  }
  void Login(CK_USER_TYPE user_type, const char* pin) {
    CK_RV rv = g_fns->C_Login(session_, user_type, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK) {
      std::cerr << "Failed to login as user type " << user_type_name(user_type) << ", error " << rv_name(rv) << std::endl;
      exit(1);
    }
  }
 protected:
  CK_SESSION_HANDLE session_;
};

class ReadOnlySessionTest : public SessionTest {
 public:
  ReadOnlySessionTest() {
    CK_FLAGS flags = CKF_SERIAL_SESSION;
    EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session_));
  }
};

class ReadWriteSessionTest : public SessionTest {
 public:
  ReadWriteSessionTest() {
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session_));
  }
};

// The following test fixtures perform a login, which is only appropriate if the token requires login.
class ROUserSessionTest : public ReadOnlySessionTest {
 public:
  ROUserSessionTest() { Login(CKU_USER, g_user_pin); }
  virtual ~ROUserSessionTest() { EXPECT_CKR_OK(g_fns->C_Logout(session_)); }
};

class RWUserSessionTest : public ReadWriteSessionTest {
 public:
  RWUserSessionTest() { Login(CKU_USER, g_user_pin); }
  virtual ~RWUserSessionTest() { EXPECT_CKR_OK(g_fns->C_Logout(session_)); }
};

class RWSOSessionTest : public ReadWriteSessionTest {
 public:
  RWSOSessionTest() { Login(CKU_SO, g_so_pin); }
  virtual ~RWSOSessionTest() { EXPECT_CKR_OK(g_fns->C_Logout(session_)); }
};

#endif  // PKCS11TEST_H
