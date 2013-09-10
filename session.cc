#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

TEST_F(PKCS11Test, ParallelSessionUnsupported) {
  // No CKF_SERIAL_SESSION => not supported
  CK_SESSION_HANDLE session;
  EXPECT_EQ(CKR_SESSION_PARALLEL_NOT_SUPPORTED, g_fns->C_OpenSession(g_slot_id, 0, NULL_PTR, NULL_PTR, &session));
}

TEST_F(ReadOnlySessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  cout << session_info_description(&session_info) << endl;
}

TEST_F(ReadWriteSessionTest, SessionInfo) {
  CK_SESSION_INFO session_info;
  EXPECT_CKR_OK(g_fns->C_GetSessionInfo(session_, &session_info));
  cout << session_info_description(&session_info) << endl;
}
