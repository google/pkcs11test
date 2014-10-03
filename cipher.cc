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
// PKCS#11 s11.8: Encryption functions (on symmetric keys)
//   C_EncryptInit
//   C_Encrypt
//   C_EncryptUpdate
//   C_EncryptFinal
// PKCS#11 s11.9: Decryption functions (on symmetric keys)
//   C_DecryptInit
//   C_Decrypt
//   C_DecryptUpdate
//   C_DecryptFinal
#include <cstdlib>
#include "pkcs11test.h"

#include <map>
#include <string>
#include <tuple>

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

struct CipherMode {
  CK_MECHANISM_TYPE keygen;
  CK_MECHANISM_TYPE mode;
};
bool operator<(const CipherMode& left, const CipherMode& right) {
  return tie(left.keygen, left.mode) < tie(right.keygen, right.mode);
}
struct CipherInfo {
  string descr;
  int blocksize;
  bool has_iv;
  int keylen;
};

map<CipherMode, CipherInfo> kCipherInfo = {
  {CipherMode({CKM_DES_KEY_GEN, CKM_DES_ECB}), CipherInfo({"DES-ECB", 8, false, -1})},
  {CipherMode({CKM_DES_KEY_GEN, CKM_DES_CBC}), CipherInfo({"DES-CBC", 8, true, -1})},
  {CipherMode({CKM_DES3_KEY_GEN, CKM_DES3_ECB}), CipherInfo({"3DES-ECB", 8, false, -1})},
  {CipherMode({CKM_DES3_KEY_GEN, CKM_DES3_CBC}), CipherInfo({"3DES-CBC", 8, true, -1})},
  {CipherMode({CKM_IDEA_KEY_GEN, CKM_IDEA_ECB}), CipherInfo({"IDEA-ECB", 8, false, -1})},
  {CipherMode({CKM_IDEA_KEY_GEN, CKM_IDEA_CBC}), CipherInfo({"IDEA-CBC", 8, true, -1})},
  {CipherMode({CKM_AES_KEY_GEN, CKM_AES_ECB}), CipherInfo({"AES-ECB", 16, false, 16})},
  {CipherMode({CKM_AES_KEY_GEN, CKM_AES_CBC}), CipherInfo({"AES-CBC", 16, true, 16})},
};

class SecretKeyTest : public ReadOnlySessionTest,
                      public ::testing::WithParamInterface<CipherMode> {
 public:
  static const int kNumBlocks = 4;
  SecretKeyTest()
    : attrs_({CKA_ENCRYPT, CKA_DECRYPT}),
      mode_(GetParam()),
      key_(session_, attrs_, mode_.keygen, kCipherInfo[mode_].keylen),
      blocksize_(kCipherInfo[mode_].blocksize),
      emits_iv_(kCipherInfo[mode_].has_iv),
      iv_(randmalloc(blocksize_)),
      plaintext_(randmalloc(kNumBlocks * blocksize_)),
      mechanism_({mode_.mode,
                  (emits_iv_ ? iv_.get() : NULL_PTR),
                  (emits_iv_ ? (CK_ULONG)blocksize_ : 0)}) {
    if (g_verbose && emits_iv_) cout << "IV: " << hex_data(iv_.get(), blocksize_) << endl;
    if (g_verbose) cout << "PT: " << hex_data(plaintext_.get(), kNumBlocks * blocksize_) << endl;
  }

 protected:
  vector<CK_ATTRIBUTE_TYPE> attrs_;
  CipherMode mode_;
  SecretKey key_;
  const int blocksize_;
  const bool emits_iv_;
  unique_ptr<CK_BYTE, freer> iv_;
  unique_ptr<CK_BYTE, freer> plaintext_;
  CK_MECHANISM mechanism_;
};

TEST_P(SecretKeyTest, EncryptDecrypt) {
  // First encrypt the data.
  CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  rv = g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, ciphertext, &ciphertext_len);
  ASSERT_CKR_OK(rv);
  EXPECT_EQ(kNumBlocks * blocksize_, ciphertext_len);
  if (g_verbose) cout << "CT: " << hex_data(ciphertext, ciphertext_len) << endl;

  // Now decrypt the data.
  rv = g_fns->C_DecryptInit(session_, &mechanism_, key_.handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = sizeof(recovered_plaintext);
  rv = g_fns->C_Decrypt(session_, ciphertext, ciphertext_len, recovered_plaintext, &recovered_plaintext_len);
  if (g_verbose) cout << "PT: " << hex_data(recovered_plaintext, recovered_plaintext_len) << endl;
  EXPECT_CKR_OK(rv);
  EXPECT_EQ(kNumBlocks * blocksize_, recovered_plaintext_len);
  EXPECT_EQ(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptDecryptParts) {
  // First encrypt the data block by block.
  CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_bufsize = sizeof(ciphertext);
  CK_ULONG ciphertext_len = 0;
  CK_BYTE_PTR part;
  CK_ULONG part_len;
  for (int block = 0; block < kNumBlocks; ++block) {
    part = ciphertext + (block * blocksize_);
    part_len = ciphertext_bufsize - (part - ciphertext);
    rv = g_fns->C_EncryptUpdate(session_,
                                plaintext_.get() + block * blocksize_, blocksize_,
                                part, &part_len);
    ASSERT_CKR_OK(rv);
    EXPECT_EQ(blocksize_, part_len);
    if (g_verbose) cout << "CT[" << block << "]: " << hex_data(part, part_len) << endl;
    ciphertext_len += part_len;
  }
  part = ciphertext + (kNumBlocks * blocksize_);
  part_len = ciphertext_len - (part - ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  ciphertext_len += part_len;
  EXPECT_EQ(kNumBlocks * blocksize_, ciphertext_len);

  // Now decrypt the data.
  rv = g_fns->C_DecryptInit(session_, &mechanism_, key_.handle());
  ASSERT_CKR_OK(rv);

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_bufsize = sizeof(recovered_plaintext);
  CK_ULONG recovered_plaintext_len = 0;
  for (int block = 0; block < kNumBlocks; ++block) {
    part = recovered_plaintext + (block * blocksize_);
    part_len = recovered_plaintext_bufsize - (part - recovered_plaintext);
    rv = g_fns->C_DecryptUpdate(session_,
                                ciphertext + (block * blocksize_), blocksize_,
                                part, &part_len);
    EXPECT_CKR_OK(rv);
    EXPECT_EQ(blocksize_, part_len);
    if (g_verbose) cout << "PT[" << block << "]: " << hex_data(part, part_len) << endl;
    recovered_plaintext_len += part_len;
  }
  part = recovered_plaintext + (kNumBlocks * blocksize_);
  part_len = recovered_plaintext_bufsize - (part - recovered_plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  ciphertext_len += part_len;
  EXPECT_EQ(kNumBlocks * blocksize_, recovered_plaintext_len);

  EXPECT_EQ(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptDecryptErrors) {
  CK_RV rv;
  // Various invalid parameters to EncryptInit
  rv = g_fns->C_EncryptInit(session_, NULL_PTR, key_.handle());
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD  || rv == CKR_MECHANISM_INVALID);
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  rv = g_fns->C_EncryptInit(session_, &mechanism, key_.handle());
  EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT, rv);

  rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  EXPECT_CKR_OK(rv);
  rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  EXPECT_CKR(CKR_OPERATION_ACTIVE, rv);

  rv = g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, NULL_PTR, NULL_PTR);
  EXPECT_CKR(CKR_ARGUMENTS_BAD, rv);

  // Error terminates the operation, so re-initialize.
  rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  EXPECT_CKR_OK(rv);
  CK_ULONG dummy_len = 0;
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, NULL_PTR, &dummy_len));
  EXPECT_EQ(kNumBlocks * blocksize_, dummy_len);

  CK_BYTE buffer[1024];
  memset(buffer, 0xAB, sizeof(buffer));
  dummy_len = sizeof(buffer);
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, buffer, &dummy_len));

  // Start a fresh encryption.
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  // Try to encrypt into a too-small buffer.
  memset(buffer, 0xAB, sizeof(buffer));
  dummy_len = 1;
  rv = g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, buffer, &dummy_len);
  EXPECT_CKR(CKR_BUFFER_TOO_SMALL, rv) << "CT: " << hex_data(buffer, dummy_len);
  EXPECT_EQ(kNumBlocks * blocksize_, dummy_len);
  EXPECT_EQ(0xAB, buffer[0]);  // Nothing written into buffer

  // Start a fresh encryption.
  dummy_len = sizeof(buffer);
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_, plaintext_.get(), kNumBlocks * blocksize_, buffer, &dummy_len));
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  // Try to encrypt an incomplete block.
  unique_ptr<CK_BYTE, freer> partial(randmalloc(blocksize_ - 1));
  CK_ULONG ciphertext_len = sizeof(buffer);
  rv = g_fns->C_Encrypt(session_, partial.get(), blocksize_ - 1, buffer, &ciphertext_len);
  EXPECT_TRUE(rv == CKR_DATA_LEN_RANGE || rv == CKR_FUNCTION_FAILED);

  // Now in part-by-part mode.
  rv = g_fns->C_EncryptInit(session_, &mechanism_, key_.handle());
  EXPECT_CKR_OK(rv);

  dummy_len = 1;
  EXPECT_CKR_OK(g_fns->C_EncryptFinal(session_, buffer, &dummy_len));
  dummy_len = 1;
  rv = g_fns->C_EncryptFinal(session_, buffer, &dummy_len);
  EXPECT_CKR(CKR_OPERATION_NOT_INITIALIZED, rv);
}

INSTANTIATE_TEST_CASE_P(Ciphers, SecretKeyTest,
                        ::testing::Values(CipherMode({CKM_DES_KEY_GEN, CKM_DES_ECB}),
                                          CipherMode({CKM_DES_KEY_GEN, CKM_DES_CBC}),
                                          CipherMode({CKM_DES3_KEY_GEN, CKM_DES3_ECB}),
                                          CipherMode({CKM_DES3_KEY_GEN, CKM_DES3_CBC}),
                                          CipherMode({CKM_AES_KEY_GEN, CKM_AES_ECB}),
                                          CipherMode({CKM_AES_KEY_GEN, CKM_AES_CBC})));

}  // namespace test
}  // namespace pkcs11
