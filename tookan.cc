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

// Test cases analogous to those described by the Tookan project:
//   http://secgroup.dais.unive.it/projects/tookan/
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadWriteSessionTest, TookanAttackA1) {
  // First, create a sensitive key k1.
  vector<CK_ATTRIBUTE_TYPE> k1_attrs = {CKA_SENSITIVE};
  SecretKey k1(session_, k1_attrs);

  // Second, create a key k2 with wrap & decrypt
  vector<CK_ATTRIBUTE_TYPE> k2_attrs = {CKA_WRAP, CKA_DECRYPT};
  SecretKey k2(session_, k2_attrs);

  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv;
  rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE ||
              rv == CKR_KEY_UNEXTRACTABLE) << " rv=" << CK_RV_(rv);

  if (rv == CKR_OK) {
    // Use k2 to decrypt the result, giving contents of k1.
    EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.handle()));
    CK_ULONG key_out_len = sizeof(data);
    rv = g_fns->C_Decrypt(session_, data, data_len, data, &key_out_len);
    if (rv == CKR_OK) {
      cerr << "Secret key is: " << hex_data(data, key_out_len) << endl;
    }
  }
}

TEST_F(RWEitherSessionTest, TookanAttackA2) {
    // First, create a sensitive key k1.
  vector<CK_ATTRIBUTE_TYPE> k1_attrs = {CKA_SENSITIVE};
  SecretKey k1(session_, k1_attrs);

  // Second, create a keypair k2 with wrap (public) & decrypt (private)
  vector<CK_ATTRIBUTE_TYPE> k2_public_attrs = {CKA_WRAP};
  vector<CK_ATTRIBUTE_TYPE> k2_private_attrs = {CKA_DECRYPT};
  KeyPair k2(session_, k2_public_attrs, k2_private_attrs);
  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv;
  rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.public_handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE ||
              rv == CKR_KEY_UNEXTRACTABLE) << " rv=" << CK_RV_(rv);

  if (rv == CKR_OK) {
    // Use k2 to decrypt the result, giving contents of k1.
    EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.private_handle()));
    CK_ULONG key_out_len = sizeof(data);
    rv = g_fns->C_Decrypt(session_, data, data_len, data, &key_out_len);
    if (rv == CKR_OK) {
      cerr << "Secret key is: " << hex_data(data, key_out_len) << endl;
    }
  }
}

TEST_F(ReadWriteSessionTest, TookanAttackA3) {
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
}

TEST_F(ReadWriteSessionTest, TookanAttackA4) {
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
}

TEST_F(ReadWriteSessionTest, TookanAttackA5a) {
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs);

  // Try to change it to be non-sensitive
  CK_ATTRIBUTE attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_SENSITIVE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_TRUE, (CK_BBOOL)data[0]);
}

TEST_F(ReadWriteSessionTest, TookanAttackA5b) {
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs);

  // Try to change it to be extractable
  CK_ATTRIBUTE attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_EXTRACTABLE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_FALSE, (CK_BBOOL)data[0]);
}

}  // namespace test
}  // namespace pkcs11
