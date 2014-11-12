/* -*- c++ -*- */
#ifndef PKCS11TEST_H
#define PKCS11TEST_H
// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
#include <vector>
#include <cstdlib>

namespace pkcs11 {

// Deleter for std::unique_ptr that handles C's malloc'ed memory.
struct freer {
  void operator()(void* p) { std::free(p); }
};

// Allocate a block of memory filled with random values.
inline std::unique_ptr<CK_BYTE, freer> randmalloc(size_t size) {
  unsigned char* p = static_cast<unsigned char*>(malloc(size));
  for (size_t ii = 0; ii < size; ++ii) {
    p[ii] = (std::rand() % 256);  // Not cryptographically safe.
  }
  return std::unique_ptr<CK_BYTE, freer>(p);
}

namespace test {

// Value to use for invalid slot IDs.
#define INVALID_SLOT_ID 88888
// Value to use for invalid session handles.
#define INVALID_SESSION_HANDLE 99999
// Value to use for invalid object handles.
#define INVALID_OBJECT_HANDLE 77777

// Mark a test case as being skipped for a reason.
void TestSkipped(const char *testcase, const char *test, const std::string& reason);
#define TEST_SKIPPED(reason) \
  do { \
    const ::testing::TestInfo* const info = ::testing::UnitTest::GetInstance()->current_test_info(); \
    TestSkipped(info->test_case_name(), info->name(), reason);          \
  } while (0)

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
#define ASSERT_CKR(expected, actual) ASSERT_EQ(CK_RV_(expected), CK_RV_(actual))
#define ASSERT_CKR_OK(val) ASSERT_CKR(CKR_OK, (val))

bool IsSpacePadded(const CK_UTF8CHAR *field, int len);
#define IS_SPACE_PADDED(field) IsSpacePadded(field, sizeof(field))
int GetInteger(const CK_CHAR *val, int len);

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
  SessionTest() : session_(INVALID_SESSION_HANDLE) {
    CK_SLOT_INFO slot_info;
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(g_slot_id, &slot_info));
    if (!(slot_info.flags & CKF_TOKEN_PRESENT)) {
      std::cerr << "Need to specify a slot ID that has a token present" << std::endl;
    }
  }
  virtual ~SessionTest() {
    if (session_ != INVALID_SESSION_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_CloseSession(session_));
    }
  }
  void Login(CK_USER_TYPE user_type, const char* pin) {
    CK_RV rv = g_fns->C_Login(session_, user_type, (CK_UTF8CHAR_PTR)pin, strlen(pin));
    if (rv != CKR_OK) {
      std::cerr << "Failed to login as user type " << user_type_name(user_type) << ", error " << rv_name(rv) << std::endl;
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

// The following test fixtures perform a login if the token flags indicate login is required.
class ROEitherSessionTest : public ReadOnlySessionTest {
 public:
  ROEitherSessionTest() { if (g_token_flags & CKF_LOGIN_REQUIRED) Login(CKU_USER, g_user_pin); }
  virtual ~ROEitherSessionTest() { if (g_token_flags & CKF_LOGIN_REQUIRED) EXPECT_CKR_OK(g_fns->C_Logout(session_)); }
};

class RWEitherSessionTest : public ReadWriteSessionTest {
 public:
  RWEitherSessionTest() { if (g_token_flags & CKF_LOGIN_REQUIRED) Login(CKU_USER, g_user_pin); }
  virtual ~RWEitherSessionTest() { if (g_token_flags & CKF_LOGIN_REQUIRED) EXPECT_CKR_OK(g_fns->C_Logout(session_)); }
};

// RAII objects for different types of session.
template <CK_FLAGS F> class Session {
 public:
  Session() { EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, F, NULL_PTR, NULL_PTR, &session_)); }
  ~Session() { EXPECT_CKR_OK(g_fns->C_CloseSession(session_)); }
  CK_SESSION_HANDLE handle() const { return session_; }
 protected:
  CK_SESSION_HANDLE session_;
};

template <CK_FLAGS F, CK_USER_TYPE U> class LoginSession : public Session<F> {
 public:
  LoginSession(const char* pin) {
      CK_RV rv = g_fns->C_Login(Session<F>::handle(), U, (CK_UTF8CHAR_PTR)pin, strlen(pin));
      if (rv != CKR_OK) {
        std::cerr << "Failed to login as user type " << user_type_name(U)
                  << " with PIN '" << pin << "', error " << rv_name(rv) << std::endl;
      }
  }
  ~LoginSession() { g_fns->C_Logout(Session<F>::handle()); }
};

typedef Session<CKF_SERIAL_SESSION> ROSession;
typedef Session<(CKF_SERIAL_SESSION|CKF_RW_SESSION)> RWSession;
typedef LoginSession<CKF_SERIAL_SESSION, CKU_USER> ROUserSession;
typedef LoginSession<(CKF_SERIAL_SESSION|CKF_RW_SESSION), CKU_USER> RWUserSession;
typedef LoginSession<(CKF_SERIAL_SESSION|CKF_RW_SESSION), CKU_SO> RWSOSession;

// Encapsulate a set of CK_ATTRIBUTES in a class.
class ObjectAttributes {
 public:
  ObjectAttributes() {
    CK_ATTRIBUTE label = {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len};
    attrs_.push_back(label);
  }
  // Constructor deliberately not explicit
  ObjectAttributes(std::vector<CK_ATTRIBUTE_TYPE>& attr_types) {
    CK_ATTRIBUTE label = {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len};
    attrs_.push_back(label);
    for (CK_ATTRIBUTE_TYPE attr_type : attr_types) {
      CK_ATTRIBUTE attr = {attr_type, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
      attrs_.push_back(attr);
    };
  }
  // Append a boolean (CK_TRUE) attribute.
  void push_back(CK_ATTRIBUTE_TYPE attr_type) {
    CK_ATTRIBUTE attr = {attr_type, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
    attrs_.push_back(attr);
  }
  // Append an arbitrary attribute.
  void push_back(const CK_ATTRIBUTE& attr) { attrs_.push_back(attr); }
  CK_ULONG size() const { return attrs_.size(); }
  CK_ATTRIBUTE_PTR data() { return &attrs_[0]; }
 private:
  friend std::ostream& operator<<(std::ostream& os, const ObjectAttributes& attrobj);
  std::vector<CK_ATTRIBUTE> attrs_;
};

inline std::ostream& operator<<(std::ostream& os, const ObjectAttributes& attrobj) {
  for (CK_ATTRIBUTE attr : attrobj.attrs_) {
    os << attribute_description(&attr) << std::endl;
  }
  return os;
}

class SecretKey {
 public:
  // Create a secret key with the given list of (boolean) attributes set to true.
  SecretKey(CK_SESSION_HANDLE session, const ObjectAttributes& attrs,
            CK_MECHANISM_TYPE keygen_mechanism = CKM_DES_KEY_GEN,
            int keylen = -1)
    : session_(session), attrs_(attrs), key_(INVALID_OBJECT_HANDLE) {
    if (keylen > 0) {
      CK_ULONG len = keylen;
      CK_ATTRIBUTE valuelen = {CKA_VALUE_LEN, &len, sizeof(CK_ULONG)};
      attrs_.push_back(valuelen);
    }
    CK_MECHANISM mechanism = {keygen_mechanism, NULL_PTR, 0};
    EXPECT_CKR_OK(g_fns->C_GenerateKey(session_, &mechanism,
                                       attrs_.data(), attrs_.size(),
                                       &key_));
  }
  ~SecretKey() {
    if (key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, key_));
    }
  }
  bool valid() const { return (key_ != INVALID_OBJECT_HANDLE); }
  CK_OBJECT_HANDLE handle() const { return key_; }
 private:
  CK_SESSION_HANDLE session_;
  ObjectAttributes attrs_;
  CK_OBJECT_HANDLE key_;
};

class KeyPair {
 public:
  // Create a keypair with the given lists of (boolean) attributes set to true.
  KeyPair(CK_SESSION_HANDLE session,
          const ObjectAttributes& public_attrs,
          const ObjectAttributes& private_attrs)
    : session_(session),
      public_attrs_(public_attrs), private_attrs_(private_attrs),
      public_key_(INVALID_OBJECT_HANDLE), private_key_(INVALID_OBJECT_HANDLE) {
    CK_ULONG modulus_bits = 1024;
    CK_ATTRIBUTE modulus = {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)};
    public_attrs_.push_back(modulus);
    CK_BYTE public_exponent_value[] = {0x1, 0x0, 0x1}; // 65537=0x010001
    CK_ATTRIBUTE public_exponent = {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)};
    public_attrs_.push_back(public_exponent);

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    EXPECT_CKR_OK(g_fns->C_GenerateKeyPair(session_, &mechanism,
                                           public_attrs_.data(), public_attrs_.size(),
                                           private_attrs_.data(), private_attrs_.size(),
                                           &public_key_, &private_key_));
  }
  ~KeyPair() {
    if (public_key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, public_key_));
    }
    if (private_key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, private_key_));
    }
  }
  bool valid() const { return (public_key_ != INVALID_OBJECT_HANDLE); }
  CK_OBJECT_HANDLE public_handle() const { return public_key_; }
  CK_OBJECT_HANDLE private_handle() const { return private_key_; }

 private:
  CK_SESSION_HANDLE session_;
  ObjectAttributes public_attrs_;
  ObjectAttributes private_attrs_;
  CK_OBJECT_HANDLE public_key_;
  CK_OBJECT_HANDLE private_key_;
};

// Test fixture for tests involving a secret key.
class SecretKeyTest : public ReadOnlySessionTest,
                      public ::testing::WithParamInterface<std::string> {
 public:
  static const int kNumBlocks = 4;
  SecretKeyTest()
    : attrs_({CKA_ENCRYPT, CKA_DECRYPT}),
      info_(kCipherInfo[GetParam()]),
      key_(session_, attrs_, info_.keygen, info_.keylen),
      iv_(randmalloc(info_.blocksize)),
      plaintext_(randmalloc(kNumBlocks * info_.blocksize)),
      mechanism_({info_.mode,
                  (info_.has_iv ? iv_.get() : NULL_PTR),
                  (info_.has_iv ? (CK_ULONG)info_.blocksize : 0)}) {
    if (g_verbose && info_.has_iv)
      std::cout << "IV: " << hex_data(iv_.get(), info_.blocksize) << std::endl;
    if (g_verbose)
      std::cout << "PT: " << hex_data(plaintext_.get(), kNumBlocks * info_.blocksize) << std::endl;
  }

 protected:
  std::vector<CK_ATTRIBUTE_TYPE> attrs_;
  CipherInfo info_;
  SecretKey key_;
  std::unique_ptr<CK_BYTE, freer> iv_;
  std::unique_ptr<CK_BYTE, freer> plaintext_;
  CK_MECHANISM mechanism_;
};

}  // namespace test

}  // namespace pkcs11

#endif  // PKCS11TEST_H
