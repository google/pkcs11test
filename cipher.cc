#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

TEST_F(ReadOnlySessionTest, DESEncryptDecrypt) {
  vector<CK_ATTRIBUTE_TYPE> attrs({CKA_ENCRYPT, CKA_DECRYPT});
  SecretKey key(session_, attrs);

  CK_BYTE plaintext[40];
  CK_ULONG plaintext_len = sizeof(plaintext);
  memcpy(plaintext, "0123456789abcdefghijklmnopqrstuvwxyzXXXX", plaintext_len);
  // First encrypt the data.
  CK_MECHANISM mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism, key.handle());
  EXPECT_CKR_OK(rv);
  if (rv != CKR_OK) return;

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  rv = g_fns->C_Encrypt(session_, plaintext, plaintext_len, ciphertext, &ciphertext_len);
  EXPECT_CKR_OK(rv);
  EXPECT_EQ(plaintext_len, ciphertext_len);
  if (rv != CKR_OK) return;

  // Now decrypt the data.
  rv = g_fns->C_DecryptInit(session_, &mechanism, key.handle());
  EXPECT_CKR_OK(rv);
  if (rv != CKR_OK) return;

  CK_BYTE recovered_plaintext[1024];
  CK_ULONG recovered_plaintext_len = sizeof(plaintext);
  rv = g_fns->C_Decrypt(session_, ciphertext, ciphertext_len, recovered_plaintext, &recovered_plaintext_len);
  EXPECT_CKR_OK(rv);
  EXPECT_EQ(plaintext_len, recovered_plaintext_len);
  EXPECT_EQ(0, memcmp(plaintext, recovered_plaintext, plaintext_len));
}

}  // namespace test
}  // namespace pkcs11
