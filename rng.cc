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
// PKCS#11 s11.15: Random number generation functions
//   C_SeedRandom
//   C_GenerateRandom

#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadOnlySessionTest, SeedRandom) {
  // Additional seed data. Not actually particularly random.
  CK_BYTE seed[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  if (g_token_flags & CKF_RNG) {
    EXPECT_CKR_OK(g_fns->C_SeedRandom(session_, seed, sizeof(seed)));
  } else {
    EXPECT_CKR(CKR_RANDOM_NO_RNG, g_fns->C_SeedRandom(session_, seed, sizeof(seed)));
  }
}

TEST(RNG, SeedRandomNoInit) {
  CK_BYTE seed[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_SeedRandom(INVALID_SLOT_ID, seed, sizeof(seed)));
}

TEST_F(ReadOnlySessionTest, SeedRandomBadArguments) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_SeedRandom(session_, nullptr, 1));
}

TEST_F(PKCS11Test, SeedRandomNoSession) {
  CK_BYTE seed[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_SeedRandom(INVALID_SLOT_ID, seed, sizeof(seed)));
}

TEST_F(ReadOnlySessionTest, GenerateRandom) {
  CK_BYTE data[1024];
  if (g_token_flags & CKF_RNG) {
    EXPECT_CKR_OK(g_fns->C_GenerateRandom(session_, data, sizeof(data)));
    EXPECT_CKR_OK(g_fns->C_GenerateRandom(session_, data, 10));
    EXPECT_CKR_OK(g_fns->C_GenerateRandom(session_, data, 100));
    CK_BYTE data2[100];
    EXPECT_CKR_OK(g_fns->C_GenerateRandom(session_, data2, 100));
    EXPECT_NE(0, memcmp(data, data2, 100));
  } else {
    EXPECT_CKR(CKR_RANDOM_NO_RNG, g_fns->C_GenerateRandom(session_, data, sizeof(data)));
  }
}

TEST(RNG, GenerateRandomNoInit) {
  CK_BYTE data[8];
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_SeedRandom(INVALID_SLOT_ID, data, sizeof(data)));
}

TEST_F(ReadOnlySessionTest, GenerateRandomBadArguments) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_GenerateRandom(session_, nullptr, 1));
}

TEST_F(ReadOnlySessionTest, GenerateRandomNone) {
  CK_BYTE data[64];
  if (g_token_flags & CKF_RNG) {
    CK_RV rv = g_fns->C_GenerateRandom(session_, data, 0);
    EXPECT_TRUE(rv == CKR_OK || rv == CKR_ARGUMENTS_BAD) << CK_RV_(rv);
  }
}

TEST_F(PKCS11Test, GenerateRandomNoSession) {
  CK_BYTE data[16];
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GenerateRandom(INVALID_SLOT_ID, data, sizeof(data)));
}

}  // namespace test
}  // namespace pkcs11
