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

#include <string>
#include <cstdlib>
#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

class DigestTest : public ReadOnlySessionTest {
 public:
  DigestTest(CK_MECHANISM_TYPE mode, int digestsize)
    : mode_(mode),
      digestsize_(digestsize),
      mechanism_({mode_, NULL_PTR, 0}),
      datalen_(std::rand() % 1024),
      data_(randmalloc(datalen_)) {
    if (g_verbose) cout << "DATA:  " << hex_data(data_.get(), min(40, datalen_))
                        << ((datalen_>40) ? "..." : "") << endl;
  }

  string TestDigest() {
    CK_RV rv = g_fns->C_DigestInit(session_, &mechanism_);
    if (rv == CKR_MECHANISM_INVALID) return "unimplemented";
    EXPECT_CKR_OK(rv);
    CK_BYTE buffer[512];
    CK_ULONG digest_len = sizeof(buffer);
    EXPECT_CKR_OK(g_fns->C_Digest(session_, data_.get(), datalen_, buffer, &digest_len));
    EXPECT_EQ(digestsize_, digest_len);
    if (g_verbose) cout << "DIGEST: " << hex_data(buffer, digest_len) << endl;
    return string(reinterpret_cast<char*>(buffer), digest_len);
  }

  string TestDigestUpdate() {
    CK_RV rv = g_fns->C_DigestInit(session_, &mechanism_);
    if (rv == CKR_MECHANISM_INVALID) return "unimplemented";
    EXPECT_CKR_OK(rv);
    const int kChunkSize = 10;
    CK_BYTE_PTR p = data_.get();
    int dataleft = datalen_;
    int count = 0;
    while (dataleft > 0) {
      int size = min(kChunkSize, dataleft);
      EXPECT_CKR_OK(g_fns->C_DigestUpdate(session_, p, size));
      p += size;
      dataleft -= size;
      ++count;
    }

    CK_BYTE buffer[512];
    CK_ULONG digest_len = sizeof(buffer);
    EXPECT_CKR_OK(g_fns->C_DigestFinal(session_, buffer, &digest_len));
    EXPECT_EQ(digestsize_, digest_len);
    if (g_verbose) cout << "DIGEST: " << hex_data(buffer, digest_len) << endl;
    return string(reinterpret_cast<char*>(buffer), digest_len);
  }

 private:
  const CK_MECHANISM_TYPE mode_;
  const int digestsize_;
  CK_MECHANISM mechanism_;
  const int datalen_;
  unique_ptr<CK_BYTE, freer> data_;
};


class Md5DigestTest : public DigestTest {
 public:
  Md5DigestTest(): DigestTest(CKM_MD5, 16) {}
};

TEST_F(Md5DigestTest, Digest) {
  string d1 = TestDigest();
  string d2 = TestDigestUpdate();
  EXPECT_EQ(hex_data(d1), hex_data(d2));
}

class Sha1DigestTest : public DigestTest {
 public:
  Sha1DigestTest(): DigestTest(CKM_SHA_1, 20) {}
};

TEST_F(Sha1DigestTest, Digest) {
  string d1 = TestDigest();
  string d2 = TestDigestUpdate();
  EXPECT_EQ(hex_data(d1), hex_data(d2));
}

class Sha256DigestTest : public DigestTest {
 public:
  Sha256DigestTest(): DigestTest(CKM_SHA256, 256/8) {}
};

TEST_F(Sha256DigestTest, Digest) {
  string d1 = TestDigest();
  string d2 = TestDigestUpdate();
  if (d1 == "unimplemented" || d2 == "unimplemented") {
    TEST_SKIPPED("SHA-256 not implemented");
  }
  EXPECT_EQ(hex_data(d1), hex_data(d2));
}

}  // namespace test
}  // namespace pkcs11
