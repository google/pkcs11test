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

#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(PKCS11Test, ParallelSessionUnsupported) {
  // No CKF_SERIAL_SESSION => not supported
  CK_SESSION_HANDLE session;
  EXPECT_CKR(CKR_SESSION_PARALLEL_NOT_SUPPORTED, g_fns->C_OpenSession(g_slot_id, 0, NULL_PTR, NULL_PTR, &session));
}

TEST_F(ReadOnlySessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  if (g_verbose) cout << session_info_description(&session_info) << endl;
  // PKCS#11 s6.7.1: When the session is initially opened, it is in [..] the "R/O Public Session" if the application has
  // no previously open sessions that are logged in
  EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_info.state);

  // Logging in changes the state.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RO_USER_FUNCTIONS, session_info.state);

  // Log out again
  EXPECT_CKR_OK(g_fns->C_Logout(session_));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_info.state);
}

TEST_F(ReadWriteSessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  if (g_verbose) cout << session_info_description(&session_info) << endl;
  // PKCS#11 s6.7.2: When the session is initially opened, it is in [..] the "R/W Public Session" if the application has
  // no previously open sessions that are logged in
  EXPECT_EQ(CKS_RW_PUBLIC_SESSION, session_info.state);

  // Logging in changes the state.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RW_USER_FUNCTIONS, session_info.state);

  // Log out again
  EXPECT_CKR_OK(g_fns->C_Logout(session_));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RW_PUBLIC_SESSION, session_info.state);
}

TEST_F(ReadWriteSessionTest, GetSetOperationState) {
  CK_ULONG len;
  CK_RV rv = g_fns->C_GetOperationState(session_, NULL_PTR, &len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("GetOperationState not supported");
    return;
  }

  // No state => OPERATION_NOT_INITIALIZED
  EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, rv);

  // Create some state
  vector<CK_ATTRIBUTE_TYPE> attrs({CKA_ENCRYPT, CKA_DECRYPT});
  SecretKey key(session_, attrs);

  CK_MECHANISM mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  rv = g_fns->C_EncryptInit(session_, &mechanism, key.handle());
  ASSERT_CKR_OK(rv);

  rv = g_fns->C_GetOperationState(session_, NULL_PTR, &len);
  if (rv != CKR_STATE_UNSAVEABLE) {
    EXPECT_CKR(CKR_OK, rv);
    unique_ptr<CK_BYTE, freer> state((CK_BYTE*)malloc(len));
    rv = g_fns->C_GetOperationState(session_, state.get(), &len);
    EXPECT_CKR_OK(rv);
    if (rv == CKR_OK) {
      rv = g_fns->C_SetOperationState(session_, state.get(), len, 0, 0);
      if (rv == CKR_KEY_NEEDED) {
        rv = g_fns->C_SetOperationState(session_, state.get(), len, key.handle(), 0);
      }
      EXPECT_CKR_OK(rv);
    }
  }
}

}  // namespace test
}  // namespace pkcs11
