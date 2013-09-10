#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

TEST_F(ReadOnlySessionTest, UserLoginWrongPIN) {
  EXPECT_EQ(CKR_PIN_INCORRECT, g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)"simply-wrong", 12));
}

TEST_F(ROUserSessionTest, UserLoginAlreadyLoggedIn) {
  EXPECT_EQ(CKR_USER_ALREADY_LOGGED_IN,
            g_fns->C_Login(session_, CKU_USER, (CK_UTF8CHAR_PTR)g_user_pin, strlen(g_user_pin)));
}

TEST_F(ReadOnlySessionTest, SOLogin) {
  EXPECT_EQ(CKR_SESSION_READ_ONLY_EXISTS,
            g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)"simply-wrong", 12));
  EXPECT_EQ(CKR_SESSION_READ_ONLY_EXISTS,
            g_fns->C_Login(session_, CKU_SO, (CK_UTF8CHAR_PTR)g_so_pin, strlen(g_so_pin)));
}
