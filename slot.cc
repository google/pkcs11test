// Tests to cover slot and token management functions (PKCS#11 s11.5):
//   C_GetSlotList
//   C_GetSlotInfo
//   C_GetTokenInfo
//   C_WaitForSlotEvent
//   C_GetMechanismList
//   C_GetMechanismInfo
//   C_InitToken
//   C_InitPIN
//   C_SetPIN

#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(PKCS11Test, EnumerateSlots) {
  // First determine how many slots.
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  unique_ptr<CK_SLOT_ID, freer> slot((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  // Retrieve slot list.
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, slot.get(), &slot_count));
  for (int ii = 0; ii < slot_count; ii++) {
    CK_SLOT_INFO slot_info = {0};
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(slot.get()[ii], &slot_info));
    if (g_verbose) cout << "slot[" << ii << "] = " << (unsigned int)slot.get()[ii] << " = " << slot_description(&slot_info) << endl;
    if (slot_info.flags & CKF_TOKEN_PRESENT) {
      CK_TOKEN_INFO token_info = {0};
      EXPECT_CKR_OK(g_fns->C_GetTokenInfo(slot.get()[ii], &token_info));
      if (g_verbose) cout << "  " << token_description(&token_info) << endl;
    }
  }
}

TEST_F(PKCS11Test, EnumerateMechanisms) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE)));
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &mechanism_count));
  for (int ii = 0; ii < mechanism_count; ii++) {
    const CK_MECHANISM_TYPE mechanism_type = mechanism.get()[ii];
    CK_MECHANISM_INFO mechanism_info;
    EXPECT_CKR_OK(g_fns->C_GetMechanismInfo(g_slot_id, mechanism_type, &mechanism_info));
    if (g_verbose) cout << "mechanism[" << ii << "]=" << mechanism_type_name(mechanism_type)
                        << " " << mechanism_info_description(&mechanism_info) << endl;
    EXPECT_LE(mechanism_info.ulMinKeySize, mechanism_info.ulMaxKeySize);
    // Check the expected functionality is available.
    CK_FLAGS expected_flags = CKF_HW;
    if (encrypt_decrypt_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_ENCRYPT;
      expected_flags |= CKF_DECRYPT;
    }
    if (sign_verify_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_SIGN;
      expected_flags |= CKF_VERIFY;
    }
    if (sign_verify_recover_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_SIGN_RECOVER;
      expected_flags |= CKF_VERIFY_RECOVER;
    }
    if (digest_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_DIGEST;
    }
    if (generate_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_GENERATE;
      expected_flags |= CKF_GENERATE_KEY_PAIR;
    }
    if (wrap_unwrap_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_WRAP;
      expected_flags |= CKF_UNWRAP;
    }
    if (derive_mechanisms.count(mechanism_type)) {
      expected_flags |= CKF_DERIVE;
    }
    // Check that the mechanism's flags are a subset of those expected.
    CK_FLAGS extra_flags = mechanism_info.flags;
    extra_flags &= ~(expected_flags);
    EXPECT_EQ(0, extra_flags);
  }
}

TEST_F(PKCS11Test, GetSlotList) {
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  unique_ptr<CK_SLOT_ID, freer> all_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, all_slots.get(), &slot_count));
  set<CK_SLOT_ID> all_slots_set;
  for (int ii = 0; ii < slot_count; ++ii) all_slots_set.insert(all_slots.get()[ii]);

  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_TRUE, NULL_PTR, &slot_count));
  unique_ptr<CK_SLOT_ID, freer> token_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_TRUE, token_slots.get(), &slot_count));

  // Every slot with a token should appear in the list of all slots.
  for (int ii = 0; ii < slot_count; ++ii) {
    EXPECT_EQ(1, all_slots_set.count(token_slots.get()[ii]));
  }
}

TEST_F(PKCS11Test, GetSlotListFailTooSmall) {
  CK_ULONG slot_count;
  EXPECT_CKR_OK(g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  if (slot_count > 1) {
    unique_ptr<CK_SLOT_ID, freer> all_slots((CK_SLOT_ID*)malloc(slot_count * sizeof(CK_SLOT_ID)));
    CK_ULONG new_slot_count = (slot_count - 1);
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, g_fns->C_GetSlotList(CK_FALSE, all_slots.get(), &new_slot_count));
    EXPECT_EQ(slot_count, new_slot_count);
  }
}

TEST_F(PKCS11Test, GetSlotListFailArgumentsBad) {
  // TODO(drysdale): reinstate (dumps core on OpenCryptoKi)
  // EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, NULL_PTR));
}

TEST_F(PKCS11Test, GetSlotInfoFail) {
  CK_SLOT_INFO slot_info = {0};
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetSlotInfo(INVALID_SLOT_ID, &slot_info));
  CK_RV rv = g_fns->C_GetSlotInfo(g_slot_id, nullptr);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED);
}

TEST_F(PKCS11Test, GetTokenInfoFail) {
  CK_TOKEN_INFO token_info = {0};
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetTokenInfo(INVALID_SLOT_ID, &token_info));
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetTokenInfo(g_slot_id, nullptr));
}

TEST_F(PKCS11Test, WaitForSlotEvent) {
  CK_SLOT_ID slot_id = -1;
  // Ask twice without blocking, to clear any pending event.
  CK_RV rv = g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) return;
  EXPECT_CKR(CKR_NO_EVENT, g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR));
}

TEST_F(PKCS11Test, GetMechanismListFailTooSmall) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  if (mechanism_count > 1) {
    unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE)));
    CK_ULONG new_mechanism_count = mechanism_count - 1;
    EXPECT_CKR(CKR_BUFFER_TOO_SMALL, g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &new_mechanism_count));
    EXPECT_EQ(mechanism_count, new_mechanism_count);
  }
}

TEST_F(PKCS11Test, GetMechanismInfoInvalid) {
  CK_MECHANISM_INFO mechanism_info;
  EXPECT_CKR(CKR_MECHANISM_INVALID, g_fns->C_GetMechanismInfo(g_slot_id, CKM_VENDOR_DEFINED + 1, &mechanism_info));
}

TEST_F(PKCS11Test, GetMechanismInfoFail) {
  CK_RV rv = g_fns->C_GetMechanismInfo(g_slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED);
}

TEST(Slot, NoInit) {
  // Check nothing works if C_Initialize has not been called.
  CK_ULONG slot_count;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetSlotList(CK_FALSE, NULL_PTR, &slot_count));
  CK_SLOT_INFO slot_info = {0};
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetSlotInfo(g_slot_id, &slot_info));
  CK_TOKEN_INFO token_info = {0};
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetTokenInfo(g_slot_id, &token_info));
  CK_SLOT_ID slot_id = -1;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR));
  CK_ULONG mechanism_count;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  CK_MECHANISM_INFO mechanism_info;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetMechanismInfo(g_slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, &mechanism_info));
  const char* label_str = "PKCS#11 Unit Test";
  CK_UTF8CHAR label[32];
  memset(label, sizeof(label), ' ');
  memcpy(label, label_str, strlen(label_str));  // Not including null terminator.
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_InitToken(INVALID_SLOT_ID, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), label));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_InitPIN(INVALID_SESSION_HANDLE, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_SetPIN(INVALID_SESSION_HANDLE,
                                                           (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin),
                                                           (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(PKCS11Test, TokenInit) {
  if (!g_init_token) {
    if (g_verbose) cout << "Skipping token initialization test" << endl;
    return;
  }
  if (g_token_flags & CKF_PROTECTED_AUTHENTICATION_PATH) {
    if (g_verbose) cout << "Skipping token initialization due to protected authentication path" << endl;
  }
  // !!!WARNING!!! - The following line will destroy all content on the token.
  EXPECT_CKR_OK(g_fns->C_InitToken(g_slot_id, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));

  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    if (g_verbose) cout << "Skipping restoration of PINs" << endl;
    return;
  }

  // Both PINs will have been reset, so need to set them, which means we need a R/W SO session.
  {
    RWSOSession session(g_reset_so_pin);
    // Restore the SO PIN to the expected value.
    EXPECT_CKR_OK(g_fns->C_SetPIN(session.handle(),
                                  (CK_UTF8CHAR_PTR)g_reset_so_pin, strlen(g_reset_so_pin),
                                  (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));
  }
  // Now set the user PIN.  Use a new session (which also checks that the SO PIN has been changed).
  {
    RWSOSession session(g_so_pin);
    EXPECT_CKR_OK(g_fns->C_InitPIN(session.handle(), (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  }
  // Check the user PIN is as expected.
  {
    ROSession session;
    EXPECT_CKR_OK(g_fns->C_Login(session.handle(), CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
    g_fns->C_Logout(session.handle());
  }
  // TODO(drysdale): figure this out
  // Some tokens (OpenCryptoKi) don't do anything on InitPIN.  Instead, log in with the reset user PIN and do SetPIN.
  {
    RWUserSession session(g_reset_user_pin);
    EXPECT_CKR_OK(g_fns->C_SetPIN(session.handle(),
                                  (CK_UTF8CHAR_PTR)g_reset_user_pin, strlen(g_reset_user_pin),
                                  (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  }
  // Check the user PIN is as expected.
  {
    ROSession session;
    EXPECT_CKR_OK(g_fns->C_Login(session.handle(), CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
    g_fns->C_Logout(session.handle());
  }

}

TEST_F(PKCS11Test, TokenInitPinIncorrect) {
  if (!g_init_token) {
    if (g_verbose) cout << "Skipping token initialization test" << endl;
    return;
  }
  const char* wrong_pin = "wrong";
  EXPECT_CKR(CKR_PIN_INCORRECT, g_fns->C_InitToken(g_slot_id, (CK_UTF8CHAR_PTR)wrong_pin, strlen(wrong_pin), g_token_label));
}

TEST_F(PKCS11Test, TokenInitInvalidSlot) {
  if (!g_init_token) {
    if (g_verbose) cout << "Skipping token initialization test" << endl;
    return;
  }
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_InitToken(INVALID_SLOT_ID, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));
}

TEST_F(ReadOnlySessionTest, TokenInitWithSession) {
  if (!g_init_token) {
    if (g_verbose) cout << "Skipping token initialization test" << endl;
    return;
  }
  EXPECT_CKR(CKR_SESSION_EXISTS, g_fns->C_InitToken(g_slot_id, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin), g_token_label));
}

}  // namespace test
}  // namespace pkcs11
