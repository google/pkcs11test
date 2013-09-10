#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

TEST_F(ReadOnlySessionTest, EnumerateObjects) {
  EXPECT_CKR_OK(g_fns->C_FindObjectsInit(session_, NULL_PTR, 0));
  while (true) {
    CK_OBJECT_HANDLE object;
    CK_ULONG object_count;
    EXPECT_CKR_OK(g_fns->C_FindObjects(session_, &object, 1, &object_count));
    if (object_count == 0) break;
    CK_ULONG object_size;
    EXPECT_CKR_OK(g_fns->C_GetObjectSize(session_, object, &object_size));
    cout << "  object x" << setw(8) << setfill('0') << hex << (unsigned int)object << " (size=" << (int)object_size << ")" << endl;

    for (int ii = 0; ii < pkcs11_attribute_count; ii++) {
      CK_BYTE buffer[2048];
      CK_ATTRIBUTE attr;
      attr.type = pkcs11_attribute_info[ii].val;
      attr.pValue = &(buffer[0]);
      attr.ulValueLen = sizeof(buffer);
      CK_RV rv = g_fns->C_GetAttributeValue(session_, object, &attr, 1);
      if (rv == CKR_OK) {
        cout << "    " << attribute_description(&attr) << endl;
      }
    }
  }
  EXPECT_CKR_OK(g_fns->C_FindObjectsFinal(session_));
}
