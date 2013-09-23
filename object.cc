#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {
namespace {

void EnumerateObjects(CK_SESSION_HANDLE session) {
  EXPECT_CKR_OK(g_fns->C_FindObjectsInit(session, NULL_PTR, 0));
  while (true) {
    CK_OBJECT_HANDLE object;
    CK_ULONG object_count;
    EXPECT_CKR_OK(g_fns->C_FindObjects(session, &object, 1, &object_count));
    if (object_count == 0) break;
    CK_ULONG object_size;
    EXPECT_CKR_OK(g_fns->C_GetObjectSize(session, object, &object_size));
    if (g_verbose) cout << "  object x" << setw(8) << setfill('0') << hex << (unsigned int)object
                        << " (size=" << (int)object_size << ")" << endl;
    if (g_verbose) cout << object_description(g_fns, session, object);
  }
  EXPECT_CKR_OK(g_fns->C_FindObjectsFinal(session));
}

}  // namespace

TEST_F(ReadOnlySessionTest, EnumerateObjects) {
  EnumerateObjects(session_);
}

TEST_F(ROUserSessionTest, EnumerateObjects) {
  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    if (g_verbose) cout << "Skipping test that requires login" << endl;
    return;
  }
  EnumerateObjects(session_);
}

}  // namespace test
}  // namespace pkcs11
