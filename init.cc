#include "gtest/gtest.h"
#include "globals.h"

using namespace std;  // So sue me

TEST(LibraryInit, Simple) {
  EXPECT_EQ(CKR_OK, g_fns->C_Initialize(NULL_PTR));
  EXPECT_EQ(CKR_OK, g_fns->C_Finalize(NULL_PTR));
}
