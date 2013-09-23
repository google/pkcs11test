#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

// This test may induce the PIN to be locked out.
TEST_F(ReadOnlySessionTest, UserLoginWrongPIN) {
  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    if (g_verbose) cout << "Skipping test that requires login" << endl;
    return;
  }
  EXPECT_CKR(CKR_PIN_INCORRECT, g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)"simply-wrong", 12));
  // Do a successful login to try to ensure the PIN isn't locked out.
  EXPECT_CKR_OK(g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
  EXPECT_CKR_OK(g_fns->C_Logout(session_));
}

TEST_F(ReadOnlySessionTest, SOLoginFail) {
  if (!(g_token_flags & CKF_LOGIN_REQUIRED)) {
    if (g_verbose) cout << "Skipping test that requires login" << endl;
    return;
  }
  // Can't login as SO in read-only session.
  EXPECT_CKR(CKR_SESSION_READ_ONLY_EXISTS,
            g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));
}


TEST_F(ROUserSessionTest, UserLoginAlreadyLoggedIn) {
  EXPECT_CKR(CKR_USER_ALREADY_LOGGED_IN,
            g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(RWUserSessionTest, SOLoginFail) {
  // Can't login as SO in read-write session if already logged in as user.
  EXPECT_CKR(CKR_SESSION_READ_ONLY_EXISTS,
            g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));
}

TEST_F(RWSOSessionTest, UserLoginFail) {
  EXPECT_CKR(CKR_USER_ANOTHER_ALREADY_LOGGED_IN,
            g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}
