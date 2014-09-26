// Copyright 2013-2014 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

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
  string hex_value = "3077"  // universal,constructed,SEQUENCE_OF,len=0x77
                       "3119"  // universal,constructed,SET_OF,len=0x19
                         "3017"  // universal,constructed,SEQUENCE_OF,len=0x17
                           "0603"  // universal,primitive,OID,len=3
                             "55040b"  // value=2.5.4.11
                           "1310" // universal,primitive,PrintableString,len=0x10
                             "476f6f676c6520436f72706f72617465"  // "Google Corporate"
                       "3113"
                         "3011"
                           "0603"
                             "55040a"
                           "130a"
                             "476f6f676c6520496e63"
                       "310b"
                         "3009"
                           "0603"
                             "550406"
                           "1302"
                             "5553"
                       "3117"
                         "3015"
                           "0609"
                             "2a864886f70d010901"
                           "1608"
                             "6472797364616c65"
                       "311f"
                         "301d"
                           "0603"
                             "550403"
                           "1316"
                             "443441453532423946393841203a3043443931363134";
  string value = hex_decode(hex_value);
  EXPECT_EQ("[{[OU=, 'Google Corporate']}, {[O=, 'Google Inc']}, {[C=, 'US']}, {[email=, 'drysdale']}, {[CN=, 'D4AE52B9F98A :0CD91614']}]",
            BERDecode((CK_BYTE_PTR)value.data(), value.size()));
}

TEST(BERDecode, DERDecodeLongTag) {
  string hex_value = ("df8028"  // private,primitive,tag=40
                      "04"  // len=4
                      "01020304");
  string value = hex_decode(hex_value);
  EXPECT_EQ("01020304", BERDecode((CK_BYTE_PTR)value.data(), value.size()));
}

TEST(BERDecode, DERDecodeIndefiniteLength) {
  string hex_value = ("f0"  // private,constructed,SEQUENCE_OF
                      "80"  // len=indefinite
                         "010101"  // universal,primitive,BOOLEAN,len=1,value=1
                         "00");  // EOC octet
  string value = hex_decode(hex_value);
  EXPECT_EQ("[01]", BERDecode((CK_BYTE_PTR)value.data(), value.size()));
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
    TEST_SKIPPED("Login required");
    return;
  }
  EnumerateObjects(session_);
}

}  // namespace test
}  // namespace pkcs11
