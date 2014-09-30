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
//
// PKCS#11 s11.7: Object management functions
//   C_CreateObject
//   C_CopyObject
//   C_DestroyObject
//   C_GetObjectSize
//   C_GetAttributeValue
//   C_SetAttributeValue
//   C_FindObjectsInit
//   C_FindObjects
//   C_FindObjectsFinal

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
      nibble = 10 + (c - 'A');
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
                             "55040b"  // value=2.5.4.11 ("OU")
                           "1310" // universal,primitive,PrintableString,len=0x10
                             "476f6f676c6520436f72706f72617465"  // "Google Corporate"
                       "3113"
                         "3011"
                           "0603"
                             "55040a"  // value=2.5.4.10 ("O")
                           "130a"
                             "476f6f676c6520496e63" // "Google Inc"
                       "310b"
                         "3009"
                           "0603"
                             "550406"  // value=2.5.4.6 ("C")
                           "1302"
                             "5553"  // "US"
                       "3117"
                         "3015"
                           "0609"
                             "2a864886f70d010901"
                           "1608"
                             "6472797364616c65"
                       "311f"
                         "301d"
                           "0603"
                             "550403" // value=2.5.4.3 ("CN")
                           "1316"
                             "443441453532423946393841203a3043443931363134";
  string value = hex_decode(hex_value);
  EXPECT_EQ("[{[OU=, 'Google Corporate']}, {[O=, 'Google Inc']}, {[C=, 'US']}, {[email=, 'drysdale']}, {[CN=, 'D4AE52B9F98A :0CD91614']}]",
            BERDecode((CK_BYTE_PTR)value.data(), value.size()));
}

TEST(BERDecode, DERDecodeLongTag) {
  string hex_value = ("DF8028"  // private,primitive,tag=40
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

TEST_F(ReadWriteSessionTest, CreateCopyDestroyObject) {
  // Create a data object.
  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_BBOOL bfalse = CK_FALSE;
  CK_UTF8CHAR app[] = "pkcs11test";
  CK_BYTE data[] = { 0xDE, 0xAD, 0xBE, 0xEF};
  CK_UTF8CHAR label[] = "OldLabel";
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
    {CKA_TOKEN, &bfalse, sizeof(bfalse)},  // Session object
    {CKA_APPLICATION, app, sizeof(app)},
    {CKA_VALUE, data, sizeof(data)},
    {CKA_LABEL, label, 8},
  };
  CK_ULONG num_attrs = sizeof(attrs) / sizeof(attrs[0]);
  CK_OBJECT_HANDLE object;
  ASSERT_CKR_OK(g_fns->C_CreateObject(session_, attrs, num_attrs, &object));

  CK_ULONG object_size;
  EXPECT_CKR_OK(g_fns->C_GetObjectSize(session_, object, &object_size));

  CK_OBJECT_HANDLE object2;
  EXPECT_CKR_OK(g_fns->C_CopyObject(session_, object, attrs, 0, &object2));

  CK_ULONG object2_size;
  EXPECT_CKR_OK(g_fns->C_GetObjectSize(session_, object, &object2_size));
  EXPECT_EQ(object_size, object2_size);

  // Check each attribute in turn.
  CK_BYTE buffer[256];
  for (size_t ii = 0; ii < num_attrs; ii++) {
    CK_ATTRIBUTE get_attr = {attrs[ii].type, buffer, sizeof(buffer)};
    EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, object2, &get_attr, 1));
    EXPECT_EQ(attrs[ii].type, get_attr.type);
    EXPECT_EQ(buffer, get_attr.pValue);
    EXPECT_EQ(attrs[ii].ulValueLen, get_attr.ulValueLen);
    EXPECT_EQ(0, memcmp(buffer, attrs[ii].pValue, attrs[ii].ulValueLen));
  }
  // Check another attribute is absent.
  CK_ATTRIBUTE get_attr = {CKA_CERTIFICATE_TYPE, buffer, sizeof(buffer)};
  EXPECT_CKR(CKR_ATTRIBUTE_TYPE_INVALID,
             g_fns->C_GetAttributeValue(session_, object2, &get_attr, 1));
  EXPECT_EQ((CK_ULONG)-1, get_attr.ulValueLen);

  // Set a new attribute on the original object.
  CK_UTF8CHAR new_label[] = "NewLabel";
  CK_ATTRIBUTE set_attr = {CKA_LABEL, new_label, 8};
  EXPECT_CKR_OK(g_fns->C_SetAttributeValue(session_, object, &set_attr, 1));

  // Unaffected on the copy, changed on the original.
  get_attr.type = CKA_LABEL;
  get_attr.ulValueLen = sizeof(buffer);
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, object2, &get_attr, 1));
  EXPECT_EQ(8, get_attr.ulValueLen);
  EXPECT_EQ(0, memcmp(label, get_attr.pValue, 5));

  get_attr.ulValueLen = sizeof(buffer);
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, object, &get_attr, 1));
  EXPECT_EQ(8, get_attr.ulValueLen);
  EXPECT_EQ(0, memcmp(new_label, get_attr.pValue, 5));

  EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, object2));
  EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, object));
}

TEST_F(ReadWriteSessionTest, CreateObjectInvalid) {
  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_BBOOL bfalse = CK_FALSE;
  CK_UTF8CHAR app[] = "pkcs11test";
  CK_BYTE data[] = { 0xDE, 0xAD, 0xBE, 0xEF};
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
    {CKA_TOKEN, &bfalse, sizeof(bfalse)},
    {CKA_APPLICATION, app, sizeof(app)},
    {CKA_VALUE, data, sizeof(data)},
  };
  CK_OBJECT_HANDLE object;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_CreateObject(INVALID_SESSION_HANDLE, attrs, sizeof(attrs)/sizeof(attrs[0]), &object));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_CreateObject(session_, attrs, sizeof(attrs)/sizeof(attrs[0]), NULL_PTR));
  CK_RV rv = g_fns->C_CreateObject(session_, NULL_PTR, sizeof(attrs)/sizeof(attrs[0]), &object);
  EXPECT_TRUE(rv == CKR_TEMPLATE_INCOMPLETE || rv == CKR_ARGUMENTS_BAD);
  rv = g_fns->C_CreateObject(session_, attrs, 0, &object);
  EXPECT_TRUE(rv == CKR_TEMPLATE_INCOMPLETE || rv == CKR_ARGUMENTS_BAD);
}

class DataObjectTest : public ReadWriteSessionTest {
 public:
  DataObjectTest() : object_(CK_INVALID_HANDLE) {
    CK_OBJECT_CLASS data_class = CKO_DATA;
    CK_BBOOL bfalse = CK_FALSE;
    CK_UTF8CHAR app[] = "pkcs11test";
    CK_BYTE data[] = { 0xDE, 0xAD, 0xBE, 0xEF};
    CK_UTF8CHAR label[] = "Label";
    CK_ATTRIBUTE attrs[] = {
      {CKA_CLASS, &data_class, sizeof(data_class)},
      {CKA_TOKEN, &bfalse, sizeof(bfalse)},
      {CKA_APPLICATION, app, sizeof(app)},
      {CKA_VALUE, data, sizeof(data)},
      {CKA_LABEL, label, 5},
    };
    EXPECT_CKR_OK(g_fns->C_CreateObject(session_, attrs, sizeof(attrs)/sizeof(attrs[0]), &object_));
  }
  ~DataObjectTest() {
    if (object_ != CK_INVALID_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, object_));
    }
  }
 protected:
    CK_OBJECT_HANDLE object_;
};

TEST_F(DataObjectTest, CopyDestroyObjectInvalid) {
  CK_ULONG object_size;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_GetObjectSize(INVALID_SESSION_HANDLE, object_, &object_size));
  EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID,
             g_fns->C_GetObjectSize(session_, INVALID_OBJECT_HANDLE, &object_size));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GetObjectSize(session_, object_, NULL_PTR));

  CK_ATTRIBUTE attr;
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_CopyObject(session_, object_, &attr, 0, NULL_PTR));
  CK_OBJECT_HANDLE object2;
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_CopyObject(session_, object_, NULL, 1, &object2));
  CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE attrs2[] = {
    {CKA_CLASS, &key_class, sizeof(key_class)},
  };
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY,
             g_fns->C_CopyObject(session_, object_, attrs2, 1, &object2));

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_DestroyObject(INVALID_SESSION_HANDLE, object_));
  EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID, g_fns->C_DestroyObject(session_, INVALID_OBJECT_HANDLE));
}

TEST_F(DataObjectTest, GetSetAttributeInvalid) {
  CK_BYTE buffer[256];
  CK_ATTRIBUTE get_attr = {CKA_LABEL, buffer, sizeof(buffer)};
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_GetAttributeValue(INVALID_SESSION_HANDLE, object_, &get_attr, 1));
  EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID,
             g_fns->C_GetAttributeValue(session_, INVALID_OBJECT_HANDLE, &get_attr, 1));
  CK_RV rv = g_fns->C_GetAttributeValue(session_, object_, NULL_PTR, 1);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_TEMPLATE_INCOMPLETE);

  CK_UTF8CHAR new_label[] = "NewLabel";
  CK_ATTRIBUTE set_attr = {CKA_LABEL, new_label, 8};
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_SetAttributeValue(INVALID_SESSION_HANDLE, object_, &set_attr, 1));
  EXPECT_CKR(CKR_OBJECT_HANDLE_INVALID,
             g_fns->C_SetAttributeValue(session_, INVALID_OBJECT_HANDLE, &set_attr, 1));

  CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
  CK_ATTRIBUTE set_attr_ro = {CKA_CLASS, &key_class, sizeof(key_class)};
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY,
             g_fns->C_SetAttributeValue(session_, object_, &set_attr_ro, 1));
}

TEST_F(DataObjectTest, FindObject) {
  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_UTF8CHAR app[] = "pkcs11test";
  CK_UTF8CHAR label[] = "Label";
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
    {CKA_APPLICATION, app, sizeof(app)},
    {CKA_LABEL, label, 5},
  };
  EXPECT_CKR_OK(g_fns->C_FindObjectsInit(session_, attrs, 3));
  CK_OBJECT_HANDLE object[5];
  CK_ULONG count;
  EXPECT_CKR_OK(g_fns->C_FindObjects(session_, object, sizeof(object), &count));
  EXPECT_EQ(1, count);
  EXPECT_EQ(object_, object[0]);
  EXPECT_CKR_OK(g_fns->C_FindObjects(session_, object, sizeof(object), &count));
  EXPECT_EQ(0, count);
  EXPECT_CKR_OK(g_fns->C_FindObjectsFinal(session_));
}

TEST_F(DataObjectTest, FindNoObject) {
  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_UTF8CHAR app[] = "pkcs11test";
  CK_UTF8CHAR label[] = "LabelSuffix";
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
    {CKA_APPLICATION, app, sizeof(app)},
    {CKA_LABEL, label, 11},
  };
  EXPECT_CKR_OK(g_fns->C_FindObjectsInit(session_, attrs, 3));
  CK_OBJECT_HANDLE object[5];
  CK_ULONG count;
  EXPECT_CKR_OK(g_fns->C_FindObjects(session_, object, sizeof(object), &count));
  EXPECT_EQ(0, count);
  EXPECT_CKR_OK(g_fns->C_FindObjectsFinal(session_));
}

TEST_F(DataObjectTest, FindObjectInvalid) {
  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_UTF8CHAR app[] = "pkcs11test";
  CK_UTF8CHAR label[] = "Label";
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
    {CKA_APPLICATION, app, sizeof(app)},
    {CKA_LABEL, label, 5},
  };

  // Find before initialization
  CK_OBJECT_HANDLE object[5];
  CK_ULONG count;
  EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED,
             g_fns->C_FindObjects(session_, object, sizeof(object), &count));

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_FindObjectsInit(INVALID_SESSION_HANDLE, attrs, 3));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_FindObjectsInit(session_, NULL_PTR, 3));
  EXPECT_CKR_OK(g_fns->C_FindObjectsInit(session_, attrs, 3));

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_FindObjects(INVALID_SESSION_HANDLE, object, sizeof(object), &count));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_FindObjects(session_, NULL_PTR, 1, &count));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_FindObjects(session_, object, sizeof(object), NULL_PTR));

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_FindObjectsFinal(INVALID_SESSION_HANDLE));
  EXPECT_CKR_OK(g_fns->C_FindObjectsFinal(session_));

  // Find after finalization
  EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED,
             g_fns->C_FindObjects(session_, object, sizeof(object), &count));
}

}  // namespace test
}  // namespace pkcs11
