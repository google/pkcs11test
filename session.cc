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
//   C_OpenSession
//   C_CloseSession
//   C_CloseAllSessions
//   C_GetSessionInfo
//   C_GetOperationState
//   C_SetOperationState
// PKCS#11 s11.16: Parallel function management functions
//   C_GetFunctionStatus
//   C_CancelFunction

#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(PKCS11Test, OpenSessionUnsupportedNonSerial) {
  // No CKF_SERIAL_SESSION => not supported
  CK_SESSION_HANDLE session = 0;
  EXPECT_CKR(CKR_SESSION_PARALLEL_NOT_SUPPORTED, g_fns->C_OpenSession(g_slot_id, 0, NULL_PTR, NULL_PTR, &session));
}

TEST_F(PKCS11Test, OpenSessionInvalidSlot) {
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  CK_SESSION_HANDLE session;
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_OpenSession(INVALID_SLOT_ID, flags, NULL_PTR, NULL_PTR, &session));
}

TEST_F(PKCS11Test, OpenSessionInvalid) {
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  CK_RV rv = g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, NULL_PTR);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST_F(PKCS11Test, ClosedSessionErrors) {
  CK_FLAGS flags = CKF_SERIAL_SESSION;
  CK_SESSION_HANDLE session;
  EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session));
  EXPECT_CKR_OK(g_fns->C_CloseSession(session));
  CK_SESSION_INFO session_info;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session, &session_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(session));
}

TEST_F(PKCS11Test, ParallelSessions) {
  CK_FLAGS ro_flags = CKF_SERIAL_SESSION;
  CK_FLAGS rw_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
  CK_SESSION_HANDLE session1;
  CK_SESSION_HANDLE session2;
  CK_SESSION_HANDLE session3;
  EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, ro_flags, NULL_PTR, NULL_PTR, &session1));
  EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, ro_flags, NULL_PTR, NULL_PTR, &session2));
  EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, rw_flags, NULL_PTR, NULL_PTR, &session3));

  CK_SESSION_INFO session1_info;
  CK_SESSION_INFO session2_info;
  CK_SESSION_INFO session3_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session3, &session3_info));
  CK_STATE original_state1 = session1_info.state;
  CK_STATE original_state2 = session2_info.state;
  CK_STATE original_state3 = session3_info.state;
  if (!(g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    // PKCS#11 s6.7.1: When the session is initially opened, it is in [..] the "R/O Public Session" if the application
    // has no previously open sessions that are logged in
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session1_info.state);
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session2_info.state);
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, session3_info.state);
  } else {
    // PKCS#11 s9.2: Token has a "protected authentication path", whereby a user can log into the token without passing
    // a PIN through the Cryptoki library, so initial state might be logged in.
  }
  EXPECT_EQ(ro_flags, session1_info.flags);
  EXPECT_EQ(ro_flags, session2_info.flags);
  EXPECT_EQ(rw_flags, session3_info.flags);
  EXPECT_EQ(g_slot_id, session1_info.slotID);
  EXPECT_EQ(g_slot_id, session2_info.slotID);
  EXPECT_EQ(g_slot_id, session3_info.slotID);

  // Login relative to one session changes all session states.
  EXPECT_CKR_OK(g_fns->C_Login(session1, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));

  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session3, &session3_info));
  EXPECT_EQ(CKS_RO_USER_FUNCTIONS, session1_info.state);
  EXPECT_EQ(CKS_RO_USER_FUNCTIONS, session2_info.state);
  EXPECT_EQ(CKS_RW_USER_FUNCTIONS, session3_info.state);

  // Logout relative to one session changes all session states.
  EXPECT_CKR_OK(g_fns->C_Logout(session3));

  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session3, &session3_info));
  EXPECT_EQ(original_state1, session1_info.state);
  EXPECT_EQ(original_state2, session2_info.state);
  EXPECT_EQ(original_state3, session3_info.state);

  // Close one session leaves the others intact.
  EXPECT_CKR_OK(g_fns->C_CloseSession(session2));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session3, &session3_info));

  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_CloseAllSessions(INVALID_SLOT_ID));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session3, &session3_info));

  EXPECT_CKR_OK(g_fns->C_CloseAllSessions(g_slot_id));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session1, &session1_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session2, &session2_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(session3, &session3_info));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(session1));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(session2));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(session3));

  EXPECT_CKR_OK(g_fns->C_CloseAllSessions(g_slot_id));
}

TEST_F(ReadOnlySessionTest, InvalidSessionInfo) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetSessionInfo(session_, NULL_PTR));
  CK_SESSION_INFO session_info;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(INVALID_SESSION_HANDLE, &session_info));
}

TEST_F(ReadWriteSessionTest, InvalidSessionInfo) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetSessionInfo(session_, NULL_PTR));
  CK_SESSION_INFO session_info;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GetSessionInfo(INVALID_SESSION_HANDLE, &session_info));
}

TEST_F(ReadOnlySessionTest, CloseSessionInvalid) {
  // PKCS#11 s11.16: Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL.
  EXPECT_CKR(CKR_FUNCTION_NOT_PARALLEL, g_fns->C_GetFunctionStatus(session_));
  EXPECT_CKR(CKR_FUNCTION_NOT_PARALLEL, g_fns->C_CancelFunction(session_));

  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(INVALID_SESSION_HANDLE));
}

TEST_F(ReadWriteSessionTest, CloseSessionInvalid) {
  // PKCS#11 s11.16: Legacy function which should simply return the value CKR_FUNCTION_NOT_PARALLEL.
  EXPECT_CKR(CKR_FUNCTION_NOT_PARALLEL, g_fns->C_GetFunctionStatus(session_));
  EXPECT_CKR(CKR_FUNCTION_NOT_PARALLEL, g_fns->C_CancelFunction(session_));

  EXPECT_EQ(CKR_SESSION_HANDLE_INVALID, g_fns->C_CloseSession(INVALID_SESSION_HANDLE));
}

TEST_F(ReadOnlySessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  if (g_verbose) cout << session_info_description(&session_info) << endl;
  EXPECT_EQ(g_slot_id, session_info.slotID);
  EXPECT_EQ(CKF_SERIAL_SESSION, session_info.flags);

  CK_STATE original_state = session_info.state;
  if (!(g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    // PKCS#11 s6.7.1: When the session is initially opened, it is in [..] the "R/O Public Session" if the application
    // has no previously open sessions that are logged in
    EXPECT_EQ(CKS_RO_PUBLIC_SESSION, session_info.state);
  } else {
    // PKCS#11 s9.2: Token has a "protected authentication path", whereby a user can log into the token without passing
    // a PIN through the Cryptoki library, so initial state might be logged in.
  }

  // Logging in changes the state.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RO_USER_FUNCTIONS, session_info.state);

  // Log out again
  EXPECT_CKR_OK(g_fns->C_Logout(session_));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(original_state, session_info.state);
}

TEST_F(ReadWriteSessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  if (g_verbose) cout << session_info_description(&session_info) << endl;
  EXPECT_EQ(g_slot_id, session_info.slotID);
  EXPECT_EQ(CKF_SERIAL_SESSION|CKF_RW_SESSION, session_info.flags);

  CK_STATE original_state = session_info.state;
  if (!(g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH)) {
    // PKCS#11 s6.7.2: When the session is initially opened, it is in [..] the "R/W Public Session" if the application
    // has no previously open sessions that are logged in
    EXPECT_EQ(CKS_RW_PUBLIC_SESSION, session_info.state);
  } else {
    // PKCS#11 s9.2: Token has a "protected authentication path", whereby a user can log into the token without passing
    // a PIN through the Cryptoki library, so initial state might be logged in.
  }

  // Logging in changes the state.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(CKS_RW_USER_FUNCTIONS, session_info.state);

  // Log out again
  EXPECT_CKR_OK(g_fns->C_Logout(session_));
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  EXPECT_EQ(original_state, session_info.state);
}

TEST_F(ReadWriteSessionTest, GetSetOperationStateInvalid) {
  CK_ULONG len;
  CK_RV rv = g_fns->C_GetOperationState(session_, NULL_PTR, &len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("GetOperationState not supported");
    return;
  }
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_GetOperationState(INVALID_SESSION_HANDLE, NULL_PTR, &len));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GetOperationState(session_, NULL_PTR, NULL_PTR));

  CK_BYTE data[1024];
  len = sizeof(data);
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_SetOperationState(INVALID_SESSION_HANDLE, data, len, 0, 0));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_SetOperationState(session_, NULL_PTR, NULL_PTR, 0, 0));
}

TEST_F(ReadWriteSessionTest, GetSetOperationState) {
  CK_ULONG len;
  CK_RV rv = g_fns->C_GetOperationState(session_, NULL_PTR, &len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("GetOperationState not supported");
    return;
  }

  // No state => OPERATION_NOT_INITIALIZED
  EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, rv) << " state len=" << len;

  // Create some state
  vector<CK_ATTRIBUTE_TYPE> attrs({CKA_ENCRYPT, CKA_DECRYPT});
  SecretKey key(session_, attrs);

  CK_MECHANISM mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  rv = g_fns->C_EncryptInit(session_, &mechanism, key.handle());
  ASSERT_CKR_OK(rv);

  // Encrypt one block.
  unique_ptr<CK_BYTE, freer> plaintext(randmalloc(16));
  CK_BYTE ciphertext[16];
  CK_BYTE_PTR output = ciphertext;
  CK_ULONG output_len = sizeof(ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptUpdate(session_, plaintext.get(), 8, output, &output_len));
  EXPECT_EQ(8, output_len);
  output += output_len;
  output_len = sizeof(ciphertext) - (output - ciphertext);

  rv = g_fns->C_GetOperationState(session_, NULL_PTR, &len);
  if (rv == CKR_STATE_UNSAVEABLE) {
    TEST_SKIPPED("GetOperationState reports state unsaveable");
    return;
  }
  EXPECT_CKR(CKR_OK, rv);
  unique_ptr<CK_BYTE, freer> state((CK_BYTE*)malloc(len));
  rv = g_fns->C_GetOperationState(session_, state.get(), &len);
  EXPECT_CKR_OK(rv);
  if (rv == CKR_OK) {
    // Set the state on a different session.
    CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    CK_SESSION_HANDLE session2;
    EXPECT_CKR_OK(g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session2));

    rv = g_fns->C_SetOperationState(session2, state.get(), len, 0, 0);
    if (rv == CKR_KEY_NEEDED) {
      rv = g_fns->C_SetOperationState(session2, state.get(), len, key.handle(), 0);
    }
    EXPECT_CKR_OK(rv);

    // Encrypt second block.
    EXPECT_CKR_OK(g_fns->C_EncryptUpdate(session2, plaintext.get() + 8, 8, output, &output_len));
    EXPECT_EQ(8, output_len);
    output += output_len;
    output_len = sizeof(ciphertext) - (output - ciphertext);
    EXPECT_CKR_OK(g_fns->C_EncryptFinal(session2, output, &output_len));

    // Check the result is the same as a one-shot encryption.
    CK_BYTE ciphertext2[16];
    output_len = sizeof(ciphertext2);
    EXPECT_CKR_OK(g_fns->C_EncryptInit(session2, &mechanism, key.handle()));
    EXPECT_CKR_OK(g_fns->C_Encrypt(session2, plaintext.get(), 16, ciphertext2, &output_len));
    EXPECT_EQ(hex_data(ciphertext2, 16), hex_data(ciphertext, 16));

    EXPECT_CKR_OK(g_fns->C_CloseSession(session2));
  }
}

}  // namespace test
}  // namespace pkcs11
