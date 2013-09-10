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
    CK_SLOT_INFO slot_info;
    EXPECT_CKR_OK(g_fns->C_GetSlotInfo(slot.get()[ii], &slot_info));
    cout << "slot[" << ii << "] = " << (unsigned int)slot.get()[ii] << " = " << slot_description(&slot_info) << endl;
    if (slot_info.flags & CKF_TOKEN_PRESENT) {
      CK_TOKEN_INFO token;
      EXPECT_CKR_OK(g_fns->C_GetTokenInfo(slot.get()[ii], &token));
      cout << "  " << token_description(&token) << endl;
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
    cout << "mechanism[" << ii << "]=" << mechanism_type_name(mechanism.get()[ii]) << mechanism_info_description(&mechanism_info) << endl;
  }
}
