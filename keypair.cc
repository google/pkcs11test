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
// PKCS#11 s11.8: Encryption functions (on asymmetric keys)
//   C_EncryptInit
//   C_Encrypt
//   C_EncryptUpdate
//   C_EncryptFinal
// PKCS#11 s11.9: Decryption functions (on asymmetric keys)
//   C_DecryptInit
//   C_Decrypt
//   C_DecryptUpdate
//   C_DecryptFinal

#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

class KeyPairTest : public ReadWriteSessionTest {
 public:
  KeyPairTest()
    : public_attrs_({CKA_ENCRYPT, CKA_TOKEN}),
      private_attrs_({CKA_DECRYPT, CKA_TOKEN}),
      keypair_(session_, public_attrs_, private_attrs_) {}
 protected:
  vector<CK_ATTRIBUTE_TYPE> public_attrs_;
  vector<CK_ATTRIBUTE_TYPE> private_attrs_;
  KeyPair keypair_;
};

struct RSAKeyData {
  string public_modulus;  // hex
  string public_exponent;  // hex
  string private_exponent;  // hex
  string prime1;  // hex
  string prime2;  // hex
  string exponent1;  // hex
  string exponent2;  // hex
  string coefficient;  // hex
};

RSAKeyData kRsaKey1 = {
  "a8b3b284af8eb50b387034a860f146c4"
  "919f318763cd6c5598c8ae4811a1e0ab"
  "c4c7e0b082d693a5e7fced675cf46685"
  "12772c0cbc64a742c6c630f533c8cc72"
  "f62ae833c40bf25842e984bb78bdbf97"
  "c0107d55bdb662f5c4e0fab9845cb514"
  "8ef7392dd3aaff93ae1e6b667bb3d424"
  "7616d4f5ba10d4cfd226de88d39f16fb",  // 128B = 1024b
  "010001",
  "53339cfdb79fc8466a655c7316aca85c"
  "55fd8f6dd898fdaf119517ef4f52e8fd"
  "8e258df93fee180fa0e4ab29693cd83b"
  "152a553d4ac4d1812b8b9fa5af0e7f55"
  "fe7304df41570926f3311f15c4d65a73"
  "2c483116ee3d3d2d0af3549ad9bf7cbf"
  "b78ad884f84d5beb04724dc7369b31de"
  "f37d0cf539e9cfcdd3de653729ead5d1",
  "d32737e7267ffe1341b2d5c0d150a81b"
  "586fb3132bed2f8d5262864a9cb9f30a"
  "f38be448598d413a172efb802c21acf1"
  "c11c520c2f26a471dcad212eac7ca39d",
  "cc8853d1d54da630fac004f471f281c7"
  "b8982d8224a490edbeb33d3e3d5cc93c"
  "4765703d1dd791642f1f116a0dd852be"
  "2419b2af72bfe9a030e860b0288b5d77",
  "0e12bf1718e9cef5599ba1c3882fe804"
  "6a90874eefce8f2ccc20e4f2741fb0a3"
  "3a3848aec9c9305fbecbd2d76819967d"
  "4671acc6431e4037968db37878e695c1",
  "95297b0f95a2fa67d00707d609dfd4fc"
  "05c89dafc2ef6d6ea55bec771ea33373"
  "4d9251e79082ecda866efef13c459e1a"
  "631386b7e354c899f5f112ca85d71583",
  "4f456c502493bdc0ed2ab756a3a6ed4d"
  "67352a697d4216e93212b127a63d5411"
  "ce6fa98d5dbefd73263e372814274381"
  "8166ed7dd63687dd2a8ca1d2f4fbd8e1"
};

}  // namespace

TEST_F(KeyPairTest, EncryptDecrypt) {
  CK_BYTE plaintext[10];
  CK_ULONG plaintext_len = sizeof(plaintext);
  memcpy(plaintext, "0123456789", plaintext_len);
  // First encrypt the data with the public key.
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism, keypair_.public_handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  rv = g_fns->C_Encrypt(session_, plaintext, plaintext_len, ciphertext, &ciphertext_len);
  ASSERT_CKR_OK(rv);
  EXPECT_EQ(128, ciphertext_len);

  // Now decrypt the data with the private key.
  rv = g_fns->C_DecryptInit(session_, &mechanism, keypair_.private_handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = sizeof(plaintext);
  rv = g_fns->C_Decrypt(session_, ciphertext, ciphertext_len, recovered_plaintext, &recovered_plaintext_len);
  EXPECT_CKR_OK(rv);
  EXPECT_EQ(plaintext_len, recovered_plaintext_len);
  EXPECT_EQ(0, memcmp(plaintext, recovered_plaintext, plaintext_len));
}

TEST_F(ReadWriteSessionTest, PublicExponent4Bytes) {
  CK_ULONG modulus_bits = 1024;
  CK_BYTE public_exponent_value[] = {0x00, 0x1, 0x0, 0x1}; // 65537=0x00010001
  vector<CK_ATTRIBUTE> public_attrs = {
    {CKA_ENCRYPT},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
    {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)},
  };
  vector<CK_ATTRIBUTE> private_attrs = {
    {CKA_DECRYPT},
  };
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_OBJECT_HANDLE public_key = INVALID_OBJECT_HANDLE;
  CK_OBJECT_HANDLE private_key = INVALID_OBJECT_HANDLE;
  EXPECT_CKR_OK(g_fns->C_GenerateKeyPair(session_, &mechanism,
                                         public_attrs.data(), public_attrs.size(),
                                         private_attrs.data(), private_attrs.size(),
                                         &public_key, &private_key));

  // Clean up
  if (public_key != INVALID_OBJECT_HANDLE) {
    EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, public_key));
  }
  if (private_key != INVALID_OBJECT_HANDLE) {
    EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, private_key));
  }
}

TEST_F(ReadWriteSessionTest, ExtractKeys) {
  vector<CK_ATTRIBUTE_TYPE> public_attrs = {CKA_ENCRYPT};
  vector<CK_ATTRIBUTE_TYPE> private_attrs = {CKA_DECRYPT, CKA_SENSITIVE};
  KeyPair keypair(session_, public_attrs, private_attrs);

  // Should be able to retrieve the modulus and public exponent.
  CK_BYTE modulus[512];
  CK_BYTE public_exponent[16];
  CK_ATTRIBUTE get_public_attrs[] = {
    {CKA_MODULUS, modulus, sizeof(modulus)},
    {CKA_PUBLIC_EXPONENT, public_exponent, sizeof(public_exponent)},
  };
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, keypair.public_handle(), get_public_attrs, 2));

  // Should not be able to retrieve the private exponent, nor the primes.
  CK_BYTE buffer[1024];
  CK_ATTRIBUTE get_private = {CKA_PRIME_1, buffer, sizeof(buffer)};
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE,
             g_fns->C_GetAttributeValue(session_, keypair.private_handle(), &get_private, 1));
  get_private.type = CKA_PRIME_2;
  get_private.ulValueLen = sizeof(buffer);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE,
             g_fns->C_GetAttributeValue(session_, keypair.private_handle(), &get_private, 1));
  get_private.type = CKA_PRIVATE_EXPONENT;
  get_private.ulValueLen = sizeof(buffer);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE,
             g_fns->C_GetAttributeValue(session_, keypair.private_handle(), &get_private, 1));

}

TEST_F(ReadWriteSessionTest, AsymmetricTokenKeyPair) {
  // Attempt to create a keypair with the private key on the token but
  // the public key not.
  CK_ULONG modulus_bits = 1024;
  CK_BYTE public_exponent_value[] = {0x1, 0x0, 0x1}; // 65537=0x010001
  CK_ATTRIBUTE public_attrs[] = {
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_TOKEN, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)},
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)},
    {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)},
  };
  CK_ATTRIBUTE private_attrs[] = {
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_TOKEN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
  };
  CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
  CK_OBJECT_HANDLE public_key;
  CK_OBJECT_HANDLE private_key;
  CK_RV rv = g_fns->C_GenerateKeyPair(session_, &mechanism,
                                      public_attrs, 5,
                                      private_attrs, 3,
                                      &public_key, &private_key);
  if (rv == CKR_OK) {
    EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, public_key));
    EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, private_key));
  } else {
    EXPECT_CKR(CKR_TEMPLATE_INCONSISTENT, rv);
  }
}

TEST_F(ReadOnlySessionTest, CreateKeyPairObjects) {
  RSAKeyData keydata = kRsaKey1;
  CK_OBJECT_HANDLE public_key;
  CK_OBJECT_HANDLE private_key;
  CK_OBJECT_CLASS public_key_class = CKO_PUBLIC_KEY;
  CK_KEY_TYPE key_type = CKK_RSA;
  string public_modulus = hex_decode(keydata.public_modulus);
  string public_exponent = hex_decode(keydata.public_exponent);
  vector<CK_ATTRIBUTE> public_attrs = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_VERIFY, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_TOKEN, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)},
    {CKA_CLASS, &public_key_class, sizeof(public_key_class)},
    {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
    {CKA_PUBLIC_EXPONENT, (CK_VOID_PTR)public_exponent.data(), public_exponent.size()},
    {CKA_MODULUS, (CK_VOID_PTR)public_modulus.data(), public_modulus.size()},
  };
  EXPECT_CKR_OK(g_fns->C_CreateObject(session_,
                                      public_attrs.data(),
                                      public_attrs.size(),
                                      &public_key));

  CK_OBJECT_CLASS private_key_class = CKO_PRIVATE_KEY;
  string private_exponent = hex_decode(keydata.private_exponent);
  vector<CK_ATTRIBUTE> private_attrs = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_SIGN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_TOKEN, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)},
    {CKA_CLASS, &private_key_class, sizeof(private_key_class)},
    {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
    {CKA_PUBLIC_EXPONENT, (CK_VOID_PTR)public_exponent.data(), public_exponent.size()},
    {CKA_PRIVATE_EXPONENT, (CK_BYTE_PTR)private_exponent.data(), private_exponent.size()},
    {CKA_MODULUS, (CK_VOID_PTR)public_modulus.data(), public_modulus.size()},
  };
  string prime1data;
  if (!keydata.prime1.empty()) {
    prime1data = hex_decode(keydata.prime1);
    private_attrs.push_back({CKA_PRIME_1, (CK_BYTE_PTR)prime1data.data(), prime1data.size()});
  }
  string prime2data;
  if (!keydata.prime2.empty()) {
    prime2data = hex_decode(keydata.prime2);
    private_attrs.push_back({CKA_PRIME_2, (CK_BYTE_PTR)prime2data.data(), prime2data.size()});
  }
  string exponent1data;
  if (!keydata.exponent1.empty()) {
    exponent1data = hex_decode(keydata.exponent1);
    private_attrs.push_back({CKA_EXPONENT_1, (CK_BYTE_PTR)exponent1data.data(), exponent1data.size()});
  }
  string exponent2data;
  if (!keydata.exponent2.empty()) {
    exponent2data = hex_decode(keydata.exponent2);
    private_attrs.push_back({CKA_EXPONENT_2, (CK_BYTE_PTR)exponent2data.data(), exponent2data.size()});
  }
  string coefficientdata;
  if (!keydata.coefficient.empty()) {
    coefficientdata = hex_decode(keydata.coefficient);
    private_attrs.push_back({CKA_COEFFICIENT, (CK_BYTE_PTR)coefficientdata.data(), coefficientdata.size()});
  }
  EXPECT_CKR_OK(g_fns->C_CreateObject(session_,
                                      private_attrs.data(),
                                      private_attrs.size(),
                                      &private_key));

  // On creating a private key object from external data, both
  // CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE should be false (as the
  // key's content has existed outside of the token).
  CK_BBOOL value;
  CK_ATTRIBUTE get_attr1 = {CKA_ALWAYS_SENSITIVE, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, private_key, &get_attr1, 1));
  EXPECT_EQ(CK_FALSE, value);
  CK_ATTRIBUTE get_attr2 = {CKA_NEVER_EXTRACTABLE, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, private_key, &get_attr2, 1));
  EXPECT_EQ(CK_FALSE, value);

  // Generated key is not local, and has no keygen mechanism.
  CK_ATTRIBUTE get_attr3 = {CKA_LOCAL, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, private_key, &get_attr3, 1));
  EXPECT_EQ(CK_FALSE, value);
  CK_MECHANISM_TYPE mech;
  CK_ATTRIBUTE get_attr4 = {CKA_KEY_GEN_MECHANISM, &mech, sizeof(mech)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, private_key, &get_attr4, 1));
  EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, mech);

  EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, public_key));
  EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, private_key));
}

}  // namespace test
}  // namespace pkcs11
