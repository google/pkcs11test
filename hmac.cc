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
// PKCS#11 s11.11: Signing and MACing functions
//   C_SignInit
//   C_Sign
//   C_SignUpdate
//   C_SignFinal
//   C_SignRecoverInit
//   C_SignRecover
// PKCS#11 s11.12: Functions for verifying signatures and MACs
//   C_VerifyInit
//   C_Verify
//   C_VerifyUpdate
//   C_VerifyFinal
//   C_VerifyRecoverInit
//   C_VerifyRecover
#include "pkcs11test.h"

#include <map>
#include <string>

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

namespace {

struct TestData {
  string key;  // Hex
  string data;  // Hex
  string hash;  // Hex
};

map<string, vector<TestData> > kTestVectors = {
  // Test vectors from RFC 2202.
  {"MD5-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "9294727a3638bb1c13f48ef8158bfc9d"},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "750c783e6ab0b503eaa86e310a5db738"}}},
  {"SHA1-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "b617318655057264e28bc0b6fb378c8ef146be00"},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"}}},
  // Test vectors from RFC 4231.
  {"SHA256-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"}, }},
  {"SHA384-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "afd03944d84895626b0825f4ab46907f15f9dadbe4101ec682aa034c7cebc59cfaea9ea9076ede7f4af152e8b2fa9cb6"},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "af45d2e376484031617f78d2b58a6b1b9c7ef464f5a01b47e42ec3736322445e8e2240ca5e69e2c78b3239ecfab21649"}, }},
  {"SHA512-HMAC",
   {{"0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", "4869205468657265",
     "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"},
    {"4a656665", "7768617420646f2079612077616e7420666f72206e6f7468696e673f",
     "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea2505549758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737"}, }},
};

}  // namespace

class HmacTest : public ReadOnlySessionTest,
                 public ::testing::WithParamInterface<string> {
 public:
  HmacTest()
    : attrs_({CKA_SIGN, CKA_VERIFY}),
      info_(kHmacInfo[GetParam()]),
      keylen_(64 + (std::rand() % 64)),
      key_data_(randmalloc(keylen_)),
      key_(INVALID_OBJECT_HANDLE),
      datalen_(std::rand() % 1024),
      data_(randmalloc(datalen_)),
      mechanism_({info_.hmac, NULL_PTR, 0}) {
    // Implementations generally only support HMAC with a GENERIC_SECRET key.
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    vector<CK_ATTRIBUTE> attrs = {
      {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
      {CKA_SIGN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
      {CKA_VERIFY, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
      {CKA_CLASS, &key_class, sizeof(key_class)},
      {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
      {CKA_VALUE, (CK_VOID_PTR)key_data_.get(), (CK_ULONG)keylen_},
    };
    EXPECT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_));
  }
  ~HmacTest() {
    if (key_ != INVALID_OBJECT_HANDLE) {
      g_fns->C_DestroyObject(session_, key_);
    }
  }

 protected:
  vector<CK_ATTRIBUTE_TYPE> attrs_;
  HmacInfo info_;
  const int keylen_;
  unique_ptr<CK_BYTE, freer> key_data_;
  CK_OBJECT_HANDLE key_;
  const int datalen_;
  unique_ptr<CK_BYTE, freer> data_;
  CK_MECHANISM mechanism_;
};

#define SKIP_IF_UNIMPLEMENTED_RV(rv) \
    if ((rv) == CKR_MECHANISM_INVALID) {  \
      stringstream ss; \
      ss << "Digest type " << mechanism_type_name(mechanism_.mechanism) << " not implemented"; \
      TEST_SKIPPED(ss.str()); \
      return; \
    }

TEST_P(HmacTest, SignVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, key_);
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));
  EXPECT_EQ(info_.mac_size, output_len);

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, key_));
  EXPECT_CKR_OK(g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

TEST_P(HmacTest, SignFailVerify) {
  CK_RV rv = g_fns->C_SignInit(session_, &mechanism_, key_);
  SKIP_IF_UNIMPLEMENTED_RV(rv);
  ASSERT_CKR_OK(rv);
  CK_BYTE output[1024];
  CK_ULONG output_len = sizeof(output);
  EXPECT_CKR_OK(g_fns->C_Sign(session_, data_.get(), datalen_, output, &output_len));

  // Corrupt one byte of the signature.
  output[0]++;

  ASSERT_CKR_OK(g_fns->C_VerifyInit(session_, &mechanism_, key_));
  EXPECT_CKR(CKR_SIGNATURE_INVALID,
             g_fns->C_Verify(session_, data_.get(), datalen_, output, output_len));
}

INSTANTIATE_TEST_CASE_P(HMACs, HmacTest,
                        ::testing::Values("MD5-HMAC",
                                          "SHA1-HMAC",
                                          "SHA256-HMAC",
                                          "SHA384-HMAC",
                                          "SHA512-HMAC"));

TEST_F(ReadOnlySessionTest, HmacTestVectors) {
  for (const auto& kv : kTestVectors) {
    vector<TestData> testcases = kTestVectors[kv.first];
    HmacInfo info = kHmacInfo[kv.first];
    for (const TestData& testcase : kv.second) {
      string key = hex_decode(testcase.key);
      CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
      CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
      vector<CK_ATTRIBUTE> attrs = {
        {CKA_LABEL, (CK_VOID_PTR)g_label, g_label_len},
        {CKA_SIGN, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_VERIFY, (CK_VOID_PTR)&g_ck_true, sizeof(CK_BBOOL)},
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, (CK_VOID_PTR)&key_type, sizeof(key_type)},
        {CKA_VALUE, (CK_VOID_PTR)key.data(), key.size()},
      };
      CK_OBJECT_HANDLE key_object;
      ASSERT_CKR_OK(g_fns->C_CreateObject(session_, attrs.data(), attrs.size(), &key_object));

      CK_MECHANISM mechanism = {info.hmac, NULL_PTR, 0};

      CK_RV rv = g_fns->C_SignInit(session_, &mechanism, key_object);
      if (rv == CKR_MECHANISM_INVALID)
        continue;
      ASSERT_CKR_OK(rv);

      string data = hex_decode(testcase.data);
      CK_BYTE output[1024];
      CK_ULONG output_len = sizeof(output);
      EXPECT_CKR_OK(g_fns->C_Sign(session_, (CK_BYTE_PTR)data.data(), data.size(), output, &output_len));
      string output_hex = hex_data(output, output_len);
      EXPECT_EQ(testcase.hash, output_hex);
    }
  }
}

}  // namespace test
}  // namespace pkcs11
