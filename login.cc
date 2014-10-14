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
//
// PKCS#11 s11.6: Session management functions
//   C_Login
//   C_Logout


#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

// This test may induce the PIN to be locked out.
TEST_F(ReadOnlySessionTest, UserLoginWrongPIN) {
  EXPECT_CKR(CKR_PIN_INCORRECT, g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)"simply-wrong", 12));

  CK_TOKEN_INFO info;
  EXPECT_CKR_OK(g_fns->C_GetTokenInfo(g_slot_id, &info));
  if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
    EXPECT_TRUE(info.flags & CKF_USER_PIN_COUNT_LOW);

  // Do a successful login to try to ensure the PIN isn't locked out.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_Logout(session_));

  EXPECT_CKR_OK(g_fns->C_GetTokenInfo(g_slot_id, &info));
  if (!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH))
    EXPECT_FALSE(info.flags & CKF_USER_PIN_COUNT_LOW);
}

TEST_F(ReadOnlySessionTest, UserLoginInvalid) {
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_Login(INVALID_SESSION_HANDLE, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR(CKR_USER_TYPE_INVALID, g_fns->C_Login(session_, 99, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(ReadOnlySessionTest, SOLoginFail) {
  if (!g_so_tests) {
    TEST_SKIPPED("No SO login available");
    return;
  }
  // Can't login as SO in read-only session.
  EXPECT_CKR(CKR_SESSION_READ_ONLY_EXISTS,
             g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));
}

TEST_F(ReadWriteSessionTest, ReadOnlySessionSOLoginFail) {
  if (!g_so_tests) {
    TEST_SKIPPED("No SO login available");
    return;
  }
  // Open a second, read-only session
  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session));

  // Presence of the read-only session prevents SO login even though there's a RW session (as login state applies across
  // all sessions).
  EXPECT_CKR(CKR_SESSION_READ_ONLY_EXISTS,
             g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));

  EXPECT_CKR_OK(g_fns->C_CloseSession(session));
}

TEST_F(ROUserSessionTest, LogoutInvalid) {
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_Logout(INVALID_SESSION_HANDLE));
}

TEST_F(ROUserSessionTest, UserLoginAlreadyLoggedIn) {
  EXPECT_CKR(CKR_USER_ALREADY_LOGGED_IN,
             g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(RWUserSessionTest, SOLoginFail) {
  // Can't login as SO in read-write session if already logged in as user.
  CK_RV rv = g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin));
  EXPECT_TRUE(rv == CKR_SESSION_READ_ONLY_EXISTS ||
              rv == CKR_USER_ANOTHER_ALREADY_LOGGED_IN) << " rv=" << CK_RV_(rv);
}

TEST_F(RWUserSessionTest, LogoutInvalid) {
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_Logout(INVALID_SESSION_HANDLE));
}

TEST_F(ReadWriteSessionTest, SOLogin) {
  if (!g_so_tests) {
    TEST_SKIPPED("No SO login available");
    return;
  }
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  CK_STATE original_state = session_info.state;
  if (!(g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    // PKCS#11 s6.7.1: When the session is initially opened, it is in [..] the "R/O Public Session" if the application
    // has no previously open sessions that are logged in
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, session_info.state);
  } else {
    // PKCS#11 s9.2: Token has a "protected authentication path", whereby a user can log into the token without passing
    // a PIN through the Cryptoki library, so initial state might be logged in.
  }

  // Now login as SO.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));

  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RW_SO_FUNCTIONS, session_info.state);

  // Log back out and expect the session state to change back.
  EXPECT_CKR_OK(g_fns->C_Logout(session_));

  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(original_state, session_info.state);

  EXPECT_CKR(CKR_USER_NOT_LOGGED_IN, g_fns->C_Logout(session_));
}

TEST_F(RWSOSessionTest, SOSessionFail) {
  // With the SO logged in, cannot open a read-only additional session.
  CK_SESSION_HANDLE session;
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  EXPECT_CKR(CKR_SESSION_READ_WRITE_SO_EXISTS,
             g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session));
}

TEST_F(RWSOSessionTest, UserLoginFail) {
  EXPECT_CKR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
             g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

}  // namespace test
}  // namespace pkcs11
