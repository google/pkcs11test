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
  CK_BYTE data[16];
  if (g_token_flags & CKF_RNG) {
    EXPECT_CKR_OK(g_fns->C_GenerateRandom(session_, data, sizeof(data)));
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

TEST_F(PKCS11Test, GenerateRandomNoSession) {
  CK_BYTE data[16];
  EXPECT_CKR(CKR_SESSION_HANDLE_INVALID, g_fns->C_GenerateRandom(INVALID_SLOT_ID, data, sizeof(data)));
}

}  // namespace test
}  // namespace pkcs11
