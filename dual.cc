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
// PKCS#11 s11.13: Dual-function cryptographic functions
//   C_DigestEncryptUpdate
//   C_DecryptDigestUpdate
//   C_SignEncryptUpdate
//   C_DecryptVerifyUpdate
#include "pkcs11test.h"

#include <sstream>

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

class DualSecretKeyTest : public SecretKeyTest {
 public:
  DualSecretKeyTest()
    : digest_info_(kDigestInfo["SHA-1"]),
      digest_mechanism_({digest_info_.type, NULL_PTR, 0}) {
  }
 protected:
  DigestInfo digest_info_;
  CK_MECHANISM digest_mechanism_;
};

}  // namespace

TEST_P(DualSecretKeyTest, DigestEncrypt) {
  // Start digest and encryption operations
  ASSERT_CKR_OK(g_fns->C_DigestInit(session_, &digest_mechanism_));
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_bufsize = sizeof(ciphertext);
  CK_ULONG ciphertext_len = 0;
  CK_BYTE_PTR part;
  CK_ULONG part_len;
  // Encrypt|Digest block-by-block
  for (int block = 0; block < kNumBlocks; ++block) {
    part = ciphertext + (block * info_.blocksize);
    part_len = ciphertext_bufsize - (part - ciphertext);
    CK_RV rv = g_fns->C_DigestEncryptUpdate(session_,
                                            plaintext_.get() + block * info_.blocksize, info_.blocksize,
                                            part, &part_len);
    if (block == 0 && rv == CKR_FUNCTION_NOT_SUPPORTED) {
      TEST_SKIPPED("Dual digest+encrypt not supported");
      return;
    }
    EXPECT_CKR_OK(rv);
    EXPECT_EQ(info_.blocksize, part_len);
    ciphertext_len += part_len;
  }
  part = ciphertext + (kNumBlocks * info_.blocksize);
  part_len = ciphertext_len - (part - ciphertext);

  // Finish both operations.
  EXPECT_CKR_OK(g_fns->C_EncryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  ciphertext_len += part_len;
  EXPECT_EQ(kNumBlocks * info_.blocksize, ciphertext_len);

  CK_BYTE buffer[512];
  CK_ULONG digest_len = sizeof(buffer);
  EXPECT_CKR_OK(g_fns->C_DigestFinal(session_, buffer, &digest_len));
  EXPECT_EQ(digest_info_.size, digest_len);

  // Now go in the opposite direction.
  ASSERT_CKR_OK(g_fns->C_DigestInit(session_, &digest_mechanism_));
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE plaintext[1024];
  CK_ULONG plaintext_bufsize = sizeof(plaintext);
  CK_ULONG plaintext_len = 0;
  // Encrypt|Digest block-by-block
  for (int block = 0; block < kNumBlocks; ++block) {
    part = plaintext + (block * info_.blocksize);
    part_len = plaintext_bufsize - (part - plaintext);
    EXPECT_CKR_OK(g_fns->C_DecryptDigestUpdate(session_,
                                               ciphertext + block * info_.blocksize, info_.blocksize,
                                               part, &part_len));
    EXPECT_EQ(info_.blocksize, part_len);
    plaintext_len += part_len;
  }
  part = plaintext + (kNumBlocks * info_.blocksize);
  part_len = plaintext_len - (part - plaintext);

  // Finish both operations.
  EXPECT_CKR_OK(g_fns->C_DecryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  plaintext_len += part_len;
  EXPECT_EQ(kNumBlocks * info_.blocksize, plaintext_len);
  EXPECT_EQ(hex_data(plaintext_.get(), kNumBlocks * info_.blocksize), hex_data(plaintext, plaintext_len));

  CK_BYTE buffer2[512];
  CK_ULONG digest2_len = sizeof(buffer2);
  EXPECT_CKR_OK(g_fns->C_DigestFinal(session_, buffer2, &digest2_len));
  EXPECT_EQ(digest_info_.size, digest2_len);

  EXPECT_EQ(hex_data(buffer, digest_len), hex_data(buffer2, digest2_len));
}

INSTANTIATE_TEST_CASE_P(Duals, DualSecretKeyTest,
                        ::testing::Values("DES-ECB",
                                          "DES-CBC",
                                          "3DES-ECB",
                                          "3DES-CBC",
                                          "AES-ECB",
                                          "AES-CBC"));

}  // namespace test
}  // namespace pkcs11
