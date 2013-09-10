#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

TEST_F(ReadOnlySessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  cout << session_info_description(&session_info) << endl;
}
