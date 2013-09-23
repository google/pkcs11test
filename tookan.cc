#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

class ObjectAttributes {
 public:
  ObjectAttributes() {
    CK_ATTRIBUTE label = {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len};
    attrs_.push_back(label);
  }
  // Constructor deliberately not explicit
  ObjectAttributes(vector<CK_ATTRIBUTE_TYPE>& attr_types) {
    CK_ATTRIBUTE label = {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len};
    attrs_.push_back(label);
    for (CK_ATTRIBUTE_TYPE attr_type : attr_types) {
      CK_ATTRIBUTE attr = {attr_type, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
      attrs_.push_back(attr);
    };
  }
  // Append a boolean (CK_TRUE) attribute.
  void push_back(CK_ATTRIBUTE_TYPE attr_type) {
    CK_ATTRIBUTE attr = {attr_type, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
    attrs_.push_back(attr);
  }
  // Append an arbitrary attribute.
  void push_back(const CK_ATTRIBUTE& attr) { attrs_.push_back(attr); }
  CK_ULONG size() const { return attrs_.size(); }
  CK_ATTRIBUTE_PTR data() { return &attrs_[0]; }
 private:
  friend ostream& operator<<(ostream& os, const ObjectAttributes& attrobj);
  vector<CK_ATTRIBUTE> attrs_;
};

ostream& operator<<(ostream& os, const ObjectAttributes& attrobj) {
  for (CK_ATTRIBUTE attr : attrobj.attrs_) {
    os << attribute_description(&attr) << endl;
  }
  return os;
}

class SecretKey {
 public:
  // Create a secret key with the given list of (boolean) attributes set to true.
  SecretKey(CK_SESSION_HANDLE session, vector<CK_ATTRIBUTE_TYPE>& attr_types)
    : session_(session), attrs_(attr_types), key_(INVALID_OBJECT_HANDLE) {
    CK_MECHANISM mechanism = {CKM_DES_KEY_GEN, NULL_PTR, 0};
    EXPECT_CKR_OK(g_fns->C_GenerateKey(session_, &mechanism,
                                       attrs_.data(), attrs_.size(),
                                       &key_));
  }
  SecretKey(CK_SESSION_HANDLE session, const ObjectAttributes& attrs)
    : session_(session), attrs_(attrs), key_(INVALID_OBJECT_HANDLE) {
    CK_MECHANISM mechanism = {CKM_DES_KEY_GEN, NULL_PTR, 0};
    EXPECT_CKR_OK(g_fns->C_GenerateKey(session_, &mechanism,
                                       attrs_.data(), attrs_.size(),
                                       &key_));
  }
  ~SecretKey() {
    if (key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, key_));
    }
  }
  bool valid() const { return (key_ != INVALID_OBJECT_HANDLE); }
  CK_OBJECT_HANDLE handle() const { return key_; }
 private:
  CK_SESSION_HANDLE session_;
  ObjectAttributes attrs_;
  CK_OBJECT_HANDLE key_;
};

class KeyPair {
 public:
  // Create a keypair with the given lists of (boolean) attributes set to true.
  KeyPair(CK_SESSION_HANDLE session,
          vector<CK_ATTRIBUTE_TYPE>& public_attr_types,
          vector<CK_ATTRIBUTE_TYPE>& private_attr_types)
    : session_(session),
      public_attrs_(public_attr_types), private_attrs_(private_attr_types),
      public_key_(INVALID_OBJECT_HANDLE), private_key_(INVALID_OBJECT_HANDLE) {

    CK_ULONG modulus_bits = 1024;
    CK_ATTRIBUTE modulus = {CKA_MODULUS_BITS, &modulus_bits, sizeof(modulus_bits)};
    public_attrs_.push_back(modulus);
    CK_BYTE public_exponent_value[] = {0x1, 0x0, 0x1}; // OpenCryptoKi requires 65537=0x00010001
    CK_ATTRIBUTE public_exponent = {CKA_PUBLIC_EXPONENT, public_exponent_value, sizeof(public_exponent_value)};
    public_attrs_.push_back(public_exponent);

    CK_MECHANISM mechanism = {CKM_RSA_PKCS_KEY_PAIR_GEN, NULL_PTR, 0};
    EXPECT_CKR_OK(g_fns->C_GenerateKeyPair(session_, &mechanism,
                                           public_attrs_.data(), public_attrs_.size(),
                                           private_attrs_.data(), private_attrs_.size(),
                                           &public_key_, &private_key_));
  }
  ~KeyPair() {
    if (public_key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, public_key_));
    }
    if (private_key_ != INVALID_OBJECT_HANDLE) {
      EXPECT_CKR_OK(g_fns->C_DestroyObject(session_, private_key_));
    }
  }
  bool valid() const { return (public_key_ != INVALID_OBJECT_HANDLE); }
  CK_OBJECT_HANDLE public_handle() const { return public_key_; }
  CK_OBJECT_HANDLE private_handle() const { return private_key_; }

 private:
  CK_SESSION_HANDLE session_;
  ObjectAttributes public_attrs_;
  ObjectAttributes private_attrs_;
  CK_OBJECT_HANDLE public_key_;
  CK_OBJECT_HANDLE private_key_;
};

TEST_F(ReadWriteSessionTest, TookanAttackA1) {
  // First, create a sensitive key k1.
  vector<CK_ATTRIBUTE_TYPE> k1_attrs = {CKA_SENSITIVE};
  SecretKey k1(session_, k1_attrs);

  // Second, create a key k2 with wrap & decrypt
  vector<CK_ATTRIBUTE_TYPE> k2_attrs = {CKA_WRAP, CKA_DECRYPT};
  SecretKey k2(session_, k2_attrs);

  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_DES_ECB, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv;
  rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.handle(), k1.handle(), data, &data_len);
  EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE ||
              rv == CKR_KEY_UNEXTRACTABLE ||
              rv == CKR_FUNCTION_NOT_SUPPORTED);

  if (rv == CKR_OK) {
    // Use k2 to decrypt the result, giving contents of k1.
    EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.handle()));
    CK_ULONG key_out_len = sizeof(data);
    rv = g_fns->C_Decrypt(session_, data, data_len, data, &key_out_len);
    if (rv == CKR_OK) {
      cerr << "Secret key is: " << hex_data(data, key_out_len) << endl;
    }
  }
}

TEST_F(RWEitherSessionTest, TookanAttackA2) {
    // First, create a sensitive key k1.
  vector<CK_ATTRIBUTE_TYPE> k1_attrs = {CKA_SENSITIVE};
  SecretKey k1(session_, k1_attrs);

  // Second, create a keypair k2 with wrap (public) & decrypt (private)
  vector<CK_ATTRIBUTE_TYPE> k2_public_attrs = {CKA_WRAP};
  vector<CK_ATTRIBUTE_TYPE> k2_private_attrs = {CKA_DECRYPT};
  KeyPair k2(session_, k2_public_attrs, k2_private_attrs);
  // Use k2 to wrap k1.
  CK_MECHANISM wrap_mechanism = {CKM_RSA_PKCS, NULL_PTR, 0};
  CK_BYTE data[4096];
  CK_ULONG data_len = sizeof(data);
  CK_RV rv;
  rv = g_fns->C_WrapKey(session_, &wrap_mechanism, k2.public_handle(), k1.handle(), data, &data_len);
  EXPECT_TRUE(rv == CKR_KEY_NOT_WRAPPABLE ||
              rv == CKR_KEY_UNEXTRACTABLE ||
              rv == CKR_FUNCTION_NOT_SUPPORTED);

  if (rv == CKR_OK) {
    // Use k2 to decrypt the result, giving contents of k1.
    EXPECT_CKR_OK(g_fns->C_DecryptInit(session_, &wrap_mechanism, k2.private_handle()));
    CK_ULONG key_out_len = sizeof(data);
    rv = g_fns->C_Decrypt(session_, data, data_len, data, &key_out_len);
    if (rv == CKR_OK) {
      cerr << "Secret key is: " << hex_data(data, key_out_len) << endl;
    }
  }
}

TEST_F(ReadWriteSessionTest, TookanAttackA3) {
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
}

TEST_F(ReadWriteSessionTest, TookanAttackA4) {
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs);
  // Retrieve its value
  CK_BYTE data[4096];
  CK_ATTRIBUTE attr = {CKA_VALUE, data, sizeof(data)};
  CK_RV rv = g_fns->C_GetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_SENSITIVE, rv);
}

TEST_F(ReadWriteSessionTest, TookanAttackA5a) {
  // Create a sensitive key.
  vector<CK_ATTRIBUTE_TYPE> key_attrs = {CKA_SENSITIVE};
  SecretKey key(session_, key_attrs);

  // Try to change it to be non-sensitive
  CK_ATTRIBUTE attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_SENSITIVE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_TRUE, (CK_BBOOL)data[0]);
}

TEST_F(ReadWriteSessionTest, TookanAttackA5b) {
  // Create a non-extractable key.
  ObjectAttributes key_attrs;
  CK_ATTRIBUTE extractable_attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  CK_ATTRIBUTE sensitive_attr = {CKA_SENSITIVE, (CK_VOID_PTR)&g_ck_false, sizeof(CK_BBOOL)};
  key_attrs.push_back(extractable_attr);
  key_attrs.push_back(sensitive_attr);
  SecretKey key(session_, key_attrs);

  // Try to change it to be extractable
  CK_ATTRIBUTE attr = {CKA_EXTRACTABLE, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)};
  CK_RV rv = g_fns->C_SetAttributeValue(session_, key.handle(), &attr, 1);
  EXPECT_CKR(CKR_ATTRIBUTE_READ_ONLY, rv);

  // Check the attribute is unchanged.
  CK_BYTE data[128];
  CK_ATTRIBUTE ret_attr = {CKA_EXTRACTABLE, data, sizeof(data)};
  EXPECT_CKR_OK(g_fns->C_GetAttributeValue(session_, key.handle(), &ret_attr, 1));
  EXPECT_EQ(CK_FALSE, (CK_BBOOL)data[0]);
}

}  // namespace test
}  // namespace pkcs11
