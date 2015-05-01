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
#include <vector>

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

struct TestData {
  string key;  // Hex
  string iv;  // Hex
  string plaintext;  // Hex
  string ciphertext;  // Hex
};

map<string, vector<TestData> > kTestVectors = {
  { "DES-ECB", {{"8000000000000000", "", "0000000000000000", "95A8D72813DAA94D"},
                {"4000000000000000", "", "0000000000000000", "0EEC1487DD8C26D5"}, }},
  { "3DES-ECB", {{"800000000000000000000000000000000000000000000000", "", "0000000000000000", "95A8D72813DAA94D"},
                 {"020202020202020202020202020202020202020202020202", "", "0202020202020202", "E127C2B61D98E6E2"}, }},
  { "AES-ECB", {{"2b7e151628aed2a6abf7158809cf4f3c", "", "6bc1bee22e409f96e93d7e117393172a", "3ad77bb40d7a3660a89ecaf32466ef97"},
                {"2b7e151628aed2a6abf7158809cf4f3c", "", "ae2d8a571e03ac9c9eb76fac45af8e51", "f5d3d58503b9699de785895a96fdbaaf"}, }},
  { "AES-CBC", {{"2b7e151628aed2a6abf7158809cf4f3c", "000102030405060708090A0B0C0D0E0F", "6bc1bee22e409f96e93d7e117393172a", "7649abac8119b246cee98e9b12e9197d"},
                {"2b7e151628aed2a6abf7158809cf4f3c", "7649ABAC8119B246CEE98E9B12E9197D", "ae2d8a571e03ac9c9eb76fac45af8e51", "5086cb9b507219ee95db113a917678b2"}, }},
};

}  // namespace

TEST_P(SecretKeyTest, EncryptDecrypt) {
  // First encrypt the data.
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 ciphertext, &ciphertext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, ciphertext_len);
  if (g_verbose) cout << "CT: " << hex_data(ciphertext, ciphertext_len) << endl;

  // Now decrypt the data.
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = sizeof(recovered_plaintext);
  EXPECT_CKR_OK(g_fns->C_Decrypt(session_,
                                 ciphertext, ciphertext_len,
                                 recovered_plaintext, &recovered_plaintext_len));
  if (g_verbose) cout << "PT: " << hex_data(recovered_plaintext, recovered_plaintext_len) << endl;
  EXPECT_EQ(kNumBlocks * info_.blocksize, recovered_plaintext_len);
  EXPECT_EQ(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptFailDecrypt) {
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 ciphertext, &ciphertext_len));

  // Corrupt a byte.
  ciphertext[0]++;

  // Now decrypt the data.
  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = sizeof(recovered_plaintext);
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_Decrypt(session_,
                                 ciphertext, ciphertext_len,
                                 recovered_plaintext, &recovered_plaintext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, recovered_plaintext_len);
  EXPECT_NE(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptDecryptGetSpace) {
  // First encrypt the data.
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = 0;
  // Provide no buffer => get OK return code and the required length.
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 NULL_PTR, &ciphertext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, ciphertext_len);

  // Provide too-small buffer => get too-small return code and the required length.
  ciphertext_len = (kNumBlocks * info_.blocksize) - 1;
  memset(ciphertext, 0xAB, sizeof(ciphertext));
  EXPECT_CKR(CKR_BUFFER_TOO_SMALL,
             g_fns->C_Encrypt(session_,
                              plaintext_.get(), kNumBlocks * info_.blocksize,
                              ciphertext, &ciphertext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, ciphertext_len);
  EXPECT_EQ(0xAB, ciphertext[0]);  // buffer unaffected

  ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 ciphertext, &ciphertext_len));

  // Now decrypt the data.
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = 0;
  // Provide no buffer => get OK return code and the required length.
  EXPECT_CKR_OK(g_fns->C_Decrypt(session_,
                                 ciphertext, ciphertext_len,
                                 NULL_PTR, &recovered_plaintext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, recovered_plaintext_len);

  // Provide too-small buffer => get too-small return code and the required length.
  recovered_plaintext_len = (kNumBlocks * info_.blocksize) - 1;
  memset(recovered_plaintext, 0xAB, sizeof(recovered_plaintext));
  EXPECT_CKR(CKR_BUFFER_TOO_SMALL,
             g_fns->C_Decrypt(session_,
                              ciphertext, ciphertext_len,
                              recovered_plaintext, &recovered_plaintext_len));
  EXPECT_EQ(kNumBlocks * info_.blocksize, recovered_plaintext_len);
  EXPECT_EQ(0xAB, recovered_plaintext[0]);  // buffer unaffected

  recovered_plaintext_len = sizeof(recovered_plaintext);
  EXPECT_CKR_OK(g_fns->C_Decrypt(session_,
                                 ciphertext, ciphertext_len,
                                 recovered_plaintext, &recovered_plaintext_len));
  EXPECT_EQ(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptDecryptParts) {
  // First encrypt the data block by block.
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_bufsize = sizeof(ciphertext);
  CK_ULONG ciphertext_len = 0;
  CK_BYTE_PTR part;
  CK_ULONG part_len;
  for (int block = 0; block < kNumBlocks; ++block) {
    part = ciphertext + (block * info_.blocksize);
    part_len = ciphertext_bufsize - (part - ciphertext);
    ASSERT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                         plaintext_.get() + block * info_.blocksize, info_.blocksize,
                                         part, &part_len));
    EXPECT_EQ(info_.blocksize, part_len);
    if (g_verbose) cout << "CT[" << block << "]: " << hex_data(part, part_len) << endl;
    ciphertext_len += part_len;
  }
  part = ciphertext + (kNumBlocks * info_.blocksize);
  part_len = ciphertext_len - (part - ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  ciphertext_len += part_len;
  EXPECT_EQ(kNumBlocks * info_.blocksize, ciphertext_len);

  // Check we get the same result as a one-shot encryption.
  CK_BYTE ciphertext2[1024];
  CK_ULONG ciphertext2_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 ciphertext2, &ciphertext2_len));
  EXPECT_EQ(hex_data(ciphertext, ciphertext_len), hex_data(ciphertext2, ciphertext2_len));

  // Now decrypt the data.
  ASSERT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_bufsize = sizeof(recovered_plaintext);
  CK_ULONG recovered_plaintext_len = 0;
  for (int block = 0; block < kNumBlocks; ++block) {
    part = recovered_plaintext + (block * info_.blocksize);
    part_len = recovered_plaintext_bufsize - (part - recovered_plaintext);
    EXPECT_CKR_OK(g_fns->C_DecryptUpdate(session_,
                                         ciphertext + (block * info_.blocksize), info_.blocksize,
                                         part, &part_len));
    EXPECT_EQ(info_.blocksize, part_len);
    if (g_verbose) cout << "PT[" << block << "]: " << hex_data(part, part_len) << endl;
    recovered_plaintext_len += part_len;
  }
  part = recovered_plaintext + (kNumBlocks * info_.blocksize);
  part_len = recovered_plaintext_bufsize - (part - recovered_plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptFinal(session_, part, &part_len));
  EXPECT_EQ(0, part_len);
  ciphertext_len += part_len;
  EXPECT_EQ(kNumBlocks * info_.blocksize, recovered_plaintext_len);

  EXPECT_EQ(0, memcmp(plaintext_.get(), recovered_plaintext, recovered_plaintext_len));
}

TEST_P(SecretKeyTest, EncryptDecryptInitInvalid) {
  CK_MECHANISM mechanism = {999, NULL_PTR, 0};
  EXPECT_CKR(CKR_MECHANISM_INVALID,
             g_fns->C_EncryptInit(session_, &mechanism, key_.handle()));
  EXPECT_CKR(CKR_MECHANISM_INVALID,
             g_fns->C_DecryptInit(session_, &mechanism, key_.handle()));

  mechanism.mechanism = info_.mode;
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_EncryptInit(INVALID_SESSION_HANDLE, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_DecryptInit(INVALID_SESSION_HANDLE, &mechanism_, key_.handle()));

  EXPECT_CKR(CKR_KEY_HANDLE_INVALID,
             g_fns->C_EncryptInit(session_, &mechanism, INVALID_OBJECT_HANDLE));
  EXPECT_CKR(CKR_KEY_HANDLE_INVALID,
             g_fns->C_DecryptInit(session_, &mechanism, INVALID_OBJECT_HANDLE));

  CK_RV rv;
  rv = g_fns->C_EncryptInit(session_, NULL_PTR, key_.handle());
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD  || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);
  rv = g_fns->C_DecryptInit(session_, NULL_PTR, key_.handle());
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD  || rv == CKR_MECHANISM_INVALID) << " rv=" << CK_RV_(rv);

  // Can't perform RSA with a symmetric key.
  CK_MECHANISM rsa_mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT,
             g_fns->C_EncryptInit(session_, &rsa_mechanism, key_.handle()));
  EXPECT_CKR(CKR_KEY_TYPE_INCONSISTENT,
             g_fns->C_DecryptInit(session_, &rsa_mechanism, key_.handle()));

  // Can't initialize the operation twice.
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_OPERATION_ACTIVE,
             g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));

  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_OPERATION_ACTIVE,
             g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
}

TEST_P(SecretKeyTest, EncryptErrors) {
  // Variety of bad arguments to C_Encrypt.  Each error terminates the
  // operation and so need re-initialization.
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_Encrypt(session_,
                              plaintext_.get(), kNumBlocks * info_.blocksize,
                              NULL_PTR, NULL_PTR));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_Encrypt(INVALID_SESSION_HANDLE,
                              plaintext_.get(), kNumBlocks * info_.blocksize,
                              ciphertext, &ciphertext_len));

  ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_Encrypt(session_,
                              NULL_PTR, info_.blocksize,
                              ciphertext, &ciphertext_len));

  // Try to encrypt an incomplete block.
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  unique_ptr<CK_BYTE, freer> partial(randmalloc(info_.blocksize - 1));
  ciphertext_len = sizeof(ciphertext);
  CK_RV rv = g_fns->C_Encrypt(session_,
                              partial.get(), info_.blocksize - 1,
                              ciphertext, &ciphertext_len);
  EXPECT_TRUE(rv == CKR_DATA_LEN_RANGE || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST_P(SecretKeyTest, DecryptErrors) {
  // First encrypt the data.
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 ciphertext, &ciphertext_len));

  // Variety of bad arguments to C_Decrypt.  Each error terminates the
  // operation and so need re-initialization.
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_Decrypt(session_,
                              ciphertext, ciphertext_len,
                              NULL_PTR, NULL_PTR));

  CK_BYTE plaintext[1024];
  CK_ULONG plaintext_len = sizeof(plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_Decrypt(INVALID_SESSION_HANDLE,
                              ciphertext, ciphertext_len,
                              plaintext, &plaintext_len));

  plaintext_len = sizeof(plaintext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_Decrypt(session_,
                              NULL_PTR, info_.blocksize,
                              plaintext, &plaintext_len));

  // Try to decrypt an incomplete block.
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  unique_ptr<CK_BYTE, freer> partial(randmalloc(info_.blocksize - 1));
  plaintext_len = sizeof(plaintext);
  CK_RV rv = g_fns->C_Decrypt(session_,
                              partial.get(), info_.blocksize - 1,
                              plaintext, &plaintext_len);
  EXPECT_TRUE(rv == CKR_DATA_LEN_RANGE ||
              rv == CKR_ENCRYPTED_DATA_LEN_RANGE ||
              rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST_P(SecretKeyTest, EncryptUpdateErrors) {
  // Variety of bad arguments to C_EncryptUpdate.  Each error terminates the
  // operation and so need re-initialization.
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_EncryptUpdate(session_,
                                    plaintext_.get(), kNumBlocks * info_.blocksize,
                                    NULL_PTR, NULL_PTR));

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_EncryptUpdate(INVALID_SESSION_HANDLE,
                                    plaintext_.get(), kNumBlocks * info_.blocksize,
                                    ciphertext, &ciphertext_len));

  ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_EncryptUpdate(session_,
                                    NULL_PTR, info_.blocksize,
                                    ciphertext, &ciphertext_len));
}

TEST_P(SecretKeyTest, EncryptModePolicing1) {
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       ciphertext, &ciphertext_len));
  // Having started an incremental operation, a one-shot operation fails.
  EXPECT_CKR(CKR_OPERATION_ACTIVE,
             g_fns->C_Encrypt(session_,
                              plaintext_.get(), kNumBlocks * info_.blocksize,
                              ciphertext, &ciphertext_len));
}

TEST_P(SecretKeyTest, EncryptModePolicing2) {
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = 0;
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_Encrypt(session_,
                                 plaintext_.get(), kNumBlocks * info_.blocksize,
                                 NULL_PTR, &ciphertext_len));
  // Having started a one-shot operation (but not yet retrieved its results),
  // an incremental operation fails.
  EXPECT_CKR(CKR_OPERATION_ACTIVE,
             g_fns->C_EncryptUpdate(session_,
                                    plaintext_.get(), kNumBlocks * info_.blocksize,
                                    ciphertext, &ciphertext_len));
}

TEST_P(SecretKeyTest, EncryptInvalidIV) {
  if (!info_.has_iv) return;
  CK_MECHANISM mechanism = {info_.mode, iv_.get(), (CK_ULONG)(info_.blocksize - 1)};
  EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID,
             g_fns->C_EncryptInit(session_, &mechanism, key_.handle()));

  /*
  // TODO: reinstate
  CK_MECHANISM mechanism2 = {info_.mode, NULL_PTR, (CK_ULONG)info_.blocksize};
  EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID,
             g_fns->C_EncryptInit(session_, &mechanism2, key_.handle()));
  */
}

TEST_P(SecretKeyTest, DecryptInvalidIV) {
  if (!info_.has_iv) return;
  CK_MECHANISM mechanism = {info_.mode, iv_.get(), (CK_ULONG)(info_.blocksize - 1)};
  EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID,
             g_fns->C_DecryptInit(session_, &mechanism, key_.handle()));

  /*
  // TODO: reinstate
  CK_MECHANISM mechanism2 = {info_.mode, NULL_PTR, (CK_ULONG)info_.blocksize};
  EXPECT_CKR(CKR_MECHANISM_PARAM_INVALID,
             g_fns->C_DecryptInit(session_, &mechanism2, key_.handle()));
  */
}

TEST_P(SecretKeyTest, DecryptUpdateErrors) {
  // First encrypt the data.
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       ciphertext, &ciphertext_len));

  // Variety of bad arguments to C_DecryptUpdate.  Each error terminates the
  // operation and so need re-initialization.
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_DecryptUpdate(session_,
                                    ciphertext, ciphertext_len,
                                    NULL_PTR, NULL_PTR));

  CK_BYTE plaintext[1024];
  CK_ULONG plaintext_len = sizeof(plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_DecryptUpdate(INVALID_SESSION_HANDLE,
                                    ciphertext, ciphertext_len,
                                    plaintext, &plaintext_len));

  plaintext_len = sizeof(plaintext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_DecryptUpdate(session_,
                                    NULL_PTR, info_.blocksize,
                                    plaintext, &plaintext_len));
}

TEST_P(SecretKeyTest, EncryptFinalImmediate) {
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  // It is valid to call EncryptFinal without any intervening EncryptUpdate operations.
  EXPECT_CKR_OK(g_fns->C_EncryptFinal(session_, ciphertext, &ciphertext_len));
  EXPECT_EQ(0, ciphertext_len);
}

TEST_P(SecretKeyTest, EncryptFinalErrors1) {
  // Variety of bad arguments to C_EncryptFinal.  Each error terminates the
  // operation and so need re-initialization.
  CK_BYTE ciphertext[1024];
  CK_BYTE_PTR output = ciphertext;
  CK_ULONG output_len = sizeof(ciphertext) - (output - ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       output, &output_len));
  output += output_len;
  output_len = sizeof(ciphertext) - (output - ciphertext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_EncryptFinal(session_, NULL_PTR, NULL_PTR));
}

TEST_P(SecretKeyTest, EncryptFinalErrors2) {
  CK_BYTE ciphertext[1024];
  CK_BYTE_PTR output = ciphertext;
  CK_ULONG output_len = sizeof(ciphertext) - (output - ciphertext);
  EXPECT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       output, &output_len));
  output += output_len;
  output_len = sizeof(ciphertext) - (output - ciphertext);
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_EncryptFinal(INVALID_SESSION_HANDLE,
                                   output, &output_len));

  // Try to encrypt an incomplete block.
  unique_ptr<CK_BYTE, freer> partial(randmalloc(info_.blocksize - 1));
  output_len = sizeof(ciphertext) - (output - ciphertext);
  CK_RV rv = g_fns->C_EncryptUpdate(session_,
                                    partial.get(), info_.blocksize - 1,
                                    output, &output_len);
  if (rv == CKR_OK) {
    output += output_len;
    output_len = sizeof(ciphertext) - (output - ciphertext);
    rv = g_fns->C_EncryptFinal(session_, output, &output_len);
    EXPECT_TRUE(rv == CKR_DATA_LEN_RANGE || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
  } else {
    EXPECT_TRUE(rv == CKR_DATA_LEN_RANGE || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
  }
}

TEST_P(SecretKeyTest, DecryptFinalErrors1) {
  // First encrypt the data.
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       ciphertext, &ciphertext_len));

  // Variety of bad arguments to C_DecryptFinal.  Each error terminates the
  // operation and so need re-initialization.
  CK_BYTE plaintext[1024];
  CK_BYTE_PTR output = plaintext;
  CK_ULONG output_len = sizeof(ciphertext) - (output - plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_DecryptUpdate(session_,
                                       ciphertext, ciphertext_len,
                                       output, &output_len));
  output += output_len;
  output_len = sizeof(ciphertext) - (output - plaintext);
  EXPECT_CKR(CKR_ARGUMENTS_BAD,
             g_fns->C_DecryptFinal(session_, NULL_PTR, NULL_PTR));
}

TEST_P(SecretKeyTest, DecryptFinalErrors2) {
  // First encrypt the data.
  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism_, key_.handle()));
  ASSERT_CKR_OK(g_fns->C_EncryptUpdate(session_,
                                       plaintext_.get(), kNumBlocks * info_.blocksize,
                                       ciphertext, &ciphertext_len));

  CK_BYTE plaintext[1024];
  CK_BYTE_PTR output = plaintext;
  CK_ULONG output_len = sizeof(ciphertext) - (output - plaintext);
  EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &mechanism_, key_.handle()));
  EXPECT_CKR_OK(g_fns->C_DecryptUpdate(session_,
                                       ciphertext, ciphertext_len,
                                       output, &output_len));
  output += output_len;
  output_len = sizeof(ciphertext) - (output - plaintext);
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID,
             g_fns->C_DecryptFinal(INVALID_SESSION_HANDLE,
                                   output, &output_len));
}

INSTANTIATE_TEST_CASE_P(Ciphers, SecretKeyTest,
                        ::testing::Values("DES-ECB",
                                          "DES-CBC",
                                          "3DES-ECB",
                                          "3DES-CBC",
                                          "AES-ECB",
                                          "AES-CBC"));

TEST_F(ReadOnlySessionTest, CreateSecretKeyAttributes) {
  string key = hex_decode("");
  CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
  CK_KEY_TYPE key_type = CKK_DES;
  vector<CK_ATTRIBUTE> attrs = {
    {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
    {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
    {CKA_CLASS, &key_class, sizeof(key_class)},
    {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
    {CKA_VALUE, (CK_VOID_PTR)key.data(), key.size()},
  };
  CK_OBJECT_HANDLE key_object;
  ASSERT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_object));

  // On creating a secret key object from external data, both
  // CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE should be false (as the
  // key's content has existed outside of the token).
  CK_BBOOL value;
  CK_ATTRIBUTE get_attr1 = {CKA_ALWAYS_SENSITIVE, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key_object, &get_attr1, 1));
  EXPECT_EQ(CK_FALSE, value);
  CK_ATTRIBUTE get_attr2 = {CKA_NEVER_EXTRACTABLE, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key_object, &get_attr2, 1));
  EXPECT_EQ(CK_FALSE, value);

  // Generated key is not local, and has no keygen mechanism.
  CK_ATTRIBUTE get_attr3 = {CKA_LOCAL, &value, sizeof(value)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key_object, &get_attr3, 1));
  EXPECT_EQ(CK_FALSE, value);
  CK_MECHANISM_TYPE mech;
  CK_ATTRIBUTE get_attr4 = {CKA_KEY_GEN_MECHANISM, &mech, sizeof(mech)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key_object, &get_attr4, 1));
  EXPECT_EQ(CK_UNAVAILABLE_INFORMATION, mech);

  ASSERT_CKR_OK(g_fns->C_DestroyObject(session_, key_object));
}

TEST_F(ReadOnlySessionTest, SecretKeyTestVectors) {
  for (const auto& kv : kTestVectors) {
    vector<TestData> testcases = kTestVectors[kv.first];
    CipherInfo info = kCipherInfo[kv.first];
    for (const TestData& testcase : kv.second) {
      if (g_verbose) {
        cout  << "KEY: " << testcase.key << endl;
        if (info.has_iv) cout << "IV:  " << testcase.iv << endl;
        cout  << "PT:  " << testcase.plaintext << endl;
        cout  << "CT:  " << testcase.ciphertext << endl;
      }
      string key = hex_decode(testcase.key);
      CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
      CK_KEY_TYPE key_type = info.keytype;
      vector<CK_ATTRIBUTE> attrs = {
        {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
        {CKA_ENCRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
        {CKA_VALUE, (CK_VOID_PTR)key.data(), key.size()},
      };
      CK_OBJECT_HANDLE key_object;
      ASSERT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_object));

      string iv = hex_decode(testcase.iv);
      CK_MECHANISM mechanism = {info.mode,
                                (info.has_iv ? (CK_BYTE_PTR)iv.data() : NULL_PTR),
                                (info.has_iv ? (CK_ULONG)info.blocksize : 0)};
      ASSERT_CKR_OK(g_fns->C_EncryptInit(session_, &mechanism, key_object));
      string plaintext = hex_decode(testcase.plaintext);
      CK_BYTE ciphertext[1024];
      CK_ULONG ciphertext_len = sizeof(ciphertext);
      ASSERT_CKR_OK(g_fns->C_Encrypt(session_,
                                     (CK_BYTE_PTR)plaintext.data(), plaintext.size(),
                                     ciphertext, &ciphertext_len));
      string expected_ciphertext = hex_decode(testcase.ciphertext);
      EXPECT_EQ(expected_ciphertext.size(), ciphertext_len);
      EXPECT_EQ(0, memcmp(expected_ciphertext.data(),
                          ciphertext,
                          expected_ciphertext.size()));
    }
  }
}

}  // namespace test
}  // namespace pkcs11
