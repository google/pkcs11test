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
// PKCS#11 s11.14: Key management functions
//   C_GenerateKey
//   C_GenerateKeyPair
//   C_WrapKey
//   C_UnwrapKey
//   C_DeriveKey
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadOnlySessionTest, GenerateKeyInvalid) {
  CK_MECHANISM mechanism = {CKM_DES_KEY_GEN, NULL_PTR, 0};
  CK_ATTRIBUTE attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE key;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_GenerateKey(INVALID_SESSION_HANDLE, &mechanism, attrs, 3, &key));
  CK_RV rv = g_fns->C_GenerateKey(session_, NULL_PTR, attrs, 3, &key);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKey(session_, &mechanism, NULL_PTR, 3, &key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKey(session_, &mechanism, attrs, 3, NULL_PTR));

}

TEST_F(ReadOnlySessionTest, GenerateKeyPairInvalid) {
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_ULONG modulus_bits = 1024;
  CK_BYTE public_exponent_value[] = {0x1, 0x0, 0x1}; // 65537=0x010001
  CK_ATTRIBUTE public_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
    {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_ATTRIBUTE private_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  CK_OBJECT_HANDLE public_key;
  CK_OBJECT_HANDLE private_key;

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
    g_fns->C_GenerateKeyPair(INVALID_SESSION_HANDLE, &mechanism,
                             public_attrs, 4,
                             private_attrs, 2,
                             &public_key, &private_key));
  CK_RV rv = g_fns->C_GenerateKeyPair(session_, NULL_PTR,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      &public_key, &private_key);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      NULL_PTR, 4,
                                      private_attrs, 2,
                                      &public_key, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      NULL_PTR, 2,
                                      &public_key, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      NULL_PTR, &private_key));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 4,
                                      private_attrs, 2,
                                      &public_key, NULL_PTR));
}


TEST_F(ReadOnlySessionTest, WrapUnwrap) {
  ObjectAttributes k1_attrs = ObjectAttributes();
  CK_ATTRIBUTE insensitive_attr = {CKA_SENSITIVE, &g_ck_false, sizeof(g_ck_false)};
  k1_attrs.push_back(insensitive_attr);
  SecretKey k1(session_, k1_attrs);

  vector<CK_ATTRIBUTE_TYPE> k2_attrs = {CKA_WRAP, CKA_UNWRAP, CKA_DECRYPT};
  SecretKey k2(session_, k2_attrs);

  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_CKR_OK(rv);

  // Use k2 to decrypt the result, giving contents of k1.
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.handle()));
  CK_BYTE key[4096];
  CK_ULONG key_out_len = sizeof(key);
  EXPECT_CKR_OK(g_fns->C_Decrypt(session_, data, data_len, key, &key_out_len));

  CK_BYTE k1_value[2048];
  CK_ATTRIBUTE get_attr = {CKA_VALUE, k1_value, sizeof(k1_value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, k1.handle(), &get_attr, 1));
  CK_ULONG k1_len = get_attr.ulValueLen;

  EXPECT_EQ(k1_len, key_out_len);
  EXPECT_EQ(hex_data(k1_value, k1_len), hex_data(key, key_out_len));

  // Unwrap to generate a key object with the same value.
  CK_OBJECT_HANDLE k3;
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_DES;
  CK_ATTRIBUTE k3_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_CLASS, &key_class, sizeof(key_class)},
    {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };
  EXPECT_CKR_OK(g_fns->C_UnwrapKey(session_, &wrap_mechanism, k2.handle(), data, data_len, k3_attrs, 5, &k3));

  CK_BYTE k3_value[2048];
  CK_ATTRIBUTE k3_get_attr = {CKA_VALUE, k3_value, sizeof(k3_value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, k3, &k3_get_attr, 1));
  CK_ULONG k3_len = get_attr.ulValueLen;
  EXPECT_EQ(hex_data(k1_value, k1_len), hex_data(k3_value, k3_len));

  g_fns->C_DestroyObject(session_, k3);
}

TEST_F(ReadOnlySessionTest, WrapInvalid) {
  ObjectAttributes k1_attrs = ObjectAttributes();
  CK_ATTRIBUTE insensitive_attr = {CKA_SENSITIVE, &g_ck_false, sizeof(g_ck_false)};
  k1_attrs.push_back(insensitive_attr);
  SecretKey k1(session_, k1_attrs);

  vector<CK_ATTRIBUTE_TYPE> k2_attrs = {CKA_WRAP, CKA_UNWRAP, CKA_DECRYPT};
  SecretKey k2(session_, k2_attrs);

  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);

  CK_RV rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_CKR_OK(rv);

  data_len = sizeof(data);
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_WrapKey(INVALID_SESSION_HANDLE, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len));
  rv = g_fns->C_WrapKey(session_, NULL_PTR, k2.handle(), k1.handle(), data, &data_len);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_WRAPPING_KEY_HANDLE_INVALID,
             g_fns->C_WrapKey(session_, &wrap_mechanism, INVALID_OBJECT_HANDLE, k1.handle(), data, &data_len));
  EXPECT_CKR(CKR_KEY_HANDLE_INVALID,
             g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), INVALID_OBJECT_HANDLE, data, &data_len));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, NULL_PTR));

  // Too-small output cases.
  EXPECT_CKR_OK(g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), NULL_PTR, &data_len));
  data_len = 1;
  EXPECT_CKR(CKR_BUFFER_TOO_SMALL,
             g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len));
}

TEST_F(ReadOnlySessionTest, UnwrapInvalid) {
  ObjectAttributes k1_attrs = ObjectAttributes();
  CK_ATTRIBUTE insensitive_attr = {CKA_SENSITIVE, &g_ck_false, sizeof(g_ck_false)};
  k1_attrs.push_back(insensitive_attr);
  SecretKey k1(session_, k1_attrs);

  vector<CK_ATTRIBUTE_TYPE> k2_attrs = {CKA_WRAP, CKA_UNWRAP, CKA_DECRYPT};
  SecretKey k2(session_, k2_attrs);

  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);

  CK_RV rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len);
  if (rv == CKR_FUNCTION_NOT_SUPPORTED) {
    // Assume implementation is symmetric w.r.t. Wrap/Unwrap.
    TEST_SKIPPED("Key wrapping not supported");
    return;
  }
  EXPECT_CKR_OK(rv);

  CK_OBJECT_HANDLE k3 = 0;
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_DES;
  CK_ATTRIBUTE k3_attrs[] = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_CLASS, &key_class, sizeof(key_class)},
    {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
  };

  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_UnwrapKey(INVALID_SESSION_HANDLE, &wrap_mechanism, k2.handle(), data, data_len, k3_attrs, 5, &k3));
  rv = g_fns->C_UnwrapKey(session_, NULL_PTR, k2.handle(), data, data_len, k3_attrs, 5, &k3);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  EXPECT_CKR(CKR_WRAPPING_KEY_HANDLE_INVALID,
             g_fns->C_UnwrapKey(session_, &wrap_mechanism, NULL_PTR, data, data_len, k3_attrs, 5, &k3));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_UnwrapKey(session_, &wrap_mechanism, k2.handle(), NULL_PTR, data_len, k3_attrs, 5, &k3));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_UnwrapKey(session_, &wrap_mechanism, k2.handle(), data, data_len, NULL_PTR, 5, &k3));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_UnwrapKey(session_, &wrap_mechanism, k2.handle(), data, data_len, k3_attrs, 5, NULL_PTR));

  g_fns->C_DestroyObject(session_, k3);  // In case of accidental creation
}

}  // namespace test
}  // namespace pkcs11
