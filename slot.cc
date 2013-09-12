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
    cout << "slot[" << ii << "] = " << (unsigned int)slot.get()[ii] << " = " << slot_description(&slot_info) << endl;
    if (slot_info.flags & CKF_TOKEN_PRESENT) {
      CK_TOKEN_INFO token_info = {0};
      EXPECT_CKR_OK(g_fns->C_GetTokenInfo(slot.get()[ii], &token_info));
      cout << "  " << token_description(&token_info) << endl;
    }
  }
}

TEST_F(PKCS11Test, EnumerateMechanisms) {
  CK_ULONG mechanism_count;
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, NULL_PTR, &mechanism_count));
  unique_ptr<CK_MECHANISM_TYPE, freer> mechanism((CK_MECHANISM_TYPE_PTR)malloc(mechanism_count * sizeof(CK_MECHANISM_TYPE)));
  EXPECT_CKR_OK(g_fns->C_GetMechanismList(g_slot_id, mechanism.get(), &mechanism_count));
  for (int ii = 0; ii < mechanism_count; ii++) {
    CK_MECHANISM_INFO mechanism_info;
    EXPECT_CKR_OK(g_fns->C_GetMechanismInfo(g_slot_id, mechanism.get()[ii], &mechanism_info));
    cout << "mechanism[" << ii << "]=" << mechanism_type_name(mechanism.get()[ii]) << " " << mechanism_info_description(&mechanism_info) << endl;
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
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetSlotInfo(123456, &slot_info));
  EXPECT_CKR(CKR_FUNCTION_FAILED, g_fns->C_GetSlotInfo(g_slot_id, nullptr));
}

TEST_F(PKCS11Test, GetTokenInfoFail) {
  CK_TOKEN_INFO token_info = {0};
  EXPECT_CKR(CKR_SLOT_ID_INVALID, g_fns->C_GetTokenInfo(123456, &token_info));
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GetTokenInfo(g_slot_id, nullptr));
}

TEST_F(PKCS11Test, WaitForSlotEvent) {
  CK_SLOT_ID slot_id = -1;
  // Ask twice without blocking, to clear any pending event.
  g_fns->C_WaitForSlotEvent(CKF_DONT_BLOCK, &slot_id, NULL_PTR);
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
  EXPECT_CKR(CKR_FUNCTION_FAILED, g_fns->C_GetMechanismInfo(g_slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR));
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
  // TODO(drysdale): Add C_InitToken, C_InitPIN, C_SetPIN
}
