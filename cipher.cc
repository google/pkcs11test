#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

class SecretKeyTest : public ReadOnlySessionTest {
 public:
  SecretKeyTest(CK_MECHANISM_TYPE keygen_mechanism, CK_MECHANISM_TYPE mode,
                int blocksize, bool emits_iv)
    : attrs_({CKA_ENCRYPT, CKA_DECRYPT}),
      key_(session_, attrs_, keygen_mechanism),
      mode_(mode),
      blocksize_(blocksize),
      emits_iv_(emits_iv) {}

  void TestEncryptDecrypt() {
    CK_BYTE iv[40];
    memcpy(iv, "0123456789abcdefghijklmnopqrstuvwxyzXXXX", blocksize_);
    CK_BYTE plaintext[40];
    CK_ULONG plaintext_len = sizeof(plaintext);
    memcpy(plaintext, "0123456789abcdefghijklmnopqrstuvwxyzXXXX", plaintext_len);
    // First encrypt the data.
    CK_MECHANISM mechanism = {mode_, (emits_iv_ ? iv : NULL_PTR), (emits_iv_ ? blocksize_ : 0)};
    CK_RV rv = g_fns->C_EncryptInit(session_, &mechanism, key_.handle());
    EXPECT_CKR_OK(rv);
    if (rv != CKR_OK) return;

    CK_BYTE ciphertext[1024];
    CK_ULONG ciphertext_len = sizeof(ciphertext);
    rv = g_fns->C_Encrypt(session_, plaintext, plaintext_len, ciphertext, &ciphertext_len);
    EXPECT_CKR_OK(rv);
    EXPECT_EQ(plaintext_len, ciphertext_len);
    if (rv != CKR_OK) return;

    // Now decrypt the data.
    rv = g_fns->C_DecryptInit(session_, &mechanism, key_.handle());
    EXPECT_CKR_OK(rv);
    if (rv != CKR_OK) return;

    CK_BYTE recovered_plaintext[1024];
    CK_ULONG recovered_plaintext_len = sizeof(plaintext);
    rv = g_fns->C_Decrypt(session_, ciphertext, ciphertext_len, recovered_plaintext, &recovered_plaintext_len);
    EXPECT_CKR_OK(rv);
    EXPECT_EQ(plaintext_len, recovered_plaintext_len);
    EXPECT_EQ(0, memcmp(plaintext, recovered_plaintext, plaintext_len));
  }

 private:
  vector<CK_ATTRIBUTE_TYPE> attrs_;
  SecretKey key_;
  CK_MECHANISM_TYPE mode_;
  int blocksize_;
  bool emits_iv_;
};


class DesEcbKeyTest : public SecretKeyTest {
 public:
  DesEcbKeyTest(): SecretKeyTest(CKM_DES_KEY_GEN, CKM_DES_ECB, 8, false) {}
};

TEST_F(DesEcbKeyTest, EncryptDecrypt) {
  TestEncryptDecrypt();
}

class DesCbcKeyTest : public SecretKeyTest {
 public:
  DesCbcKeyTest(): SecretKeyTest(CKM_DES_KEY_GEN, CKM_DES_CBC, 8, true) {}
};

TEST_F(DesCbcKeyTest, EncryptDecrypt) {
  TestEncryptDecrypt();
}

}  // namespace test
}  // namespace pkcs11
