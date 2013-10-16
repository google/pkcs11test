#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

class KeyPairTest : public ReadWriteSessionTest {
 public:
  KeyPairTest()
    : public_attrs_({CKA_ENCRYPT}),
      private_attrs_({CKA_DECRYPT}),
      keypair_(session_, public_attrs_, private_attrs_) {}
 protected:
  vector<CK_ATTRIBUTE_TYPE> public_attrs_;
  vector<CK_ATTRIBUTE_TYPE> private_attrs_;
  KeyPair keypair_;
};

TEST_F(KeyPairTest, EncryptDecrypt) {
  CK_BYTE plaintext[10];
  CK_ULONG plaintext_len = sizeof(plaintext);
  memcpy(plaintext, "0123456789", plaintext_len);
  // First encrypt the data with the public key.
  CK_MECHANISM mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism, keypair_.public_handle());
  EXPECT_CKR_OK(rv);
  if (rv != CKR_OK) return;

  CK_BYTE ciphertext[1024];
  CK_ULONG ciphertext_len = sizeof(ciphertext);
  rv = g_fns->C_Encrypt(session_, plaintext, plaintext_len, ciphertext, &ciphertext_len);
  EXPECT_CKR_OK(rv);
  EXPECT_EQ(128, ciphertext_len);
  if (rv != CKR_OK) return;

  // Now decrypt the data with the private key.
  rv = g_fns->C_DecryptInit(session_, &mechanism, keypair_.private_handle());
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
