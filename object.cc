#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {
namespace {

string hex_decode(string hex_value) {
  bool high_nibble = true;
  stringstream ss;
  int value = 0;
  for (char c : hex_value) {
    int nibble;
    if (c >= '0' && c <= '9') {
      nibble = c - '0';
    } else if (c >= 'a' && c <= 'f') {
      nibble = 10 + (c - 'a');
    } else if (c >= 'A' && c <= 'F') {
      nibble = 10 + (c - 'a');
    } else {
      exit(1);
    }
    if (high_nibble) {
      value = (nibble << 4);
    } else {
      value |= nibble;
      ss << static_cast<char>(value);
    }
    high_nibble = !high_nibble;
  }
  return ss.str();
}

TEST(BERDecode, DERDecode) {
  string hex_value = "307731193017060355040b1310476f6f676c6520436f72706f7261746531133011060355040a130a476f6f676c6520496e63310b30090603550406130255533117301506092a864886f70d01090116086472797364616c65311f301d06035504031316443441453532423946393841203a3043443931363134";
  string value = hex_decode(hex_value);
  EXPECT_EQ("[{[OU=, 'Google Corporate']}, {[O=, 'Google Inc']}, {[C=, 'US']}, {[email=, 'drysdale']}, {[CN=, 'D4AE52B9F98A :0CD91614']}]",
            BERDecode((CK_BYTE_PTR)value.data(), value.size()));
}

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
