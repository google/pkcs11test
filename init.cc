#include "pkcs11test.h"

using namespace std;  // So sue me

// Explicitly test Initialize/Finalize.
TEST(Init, Simple) {
  EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgs) {
  CK_C_INITIALIZE_ARGS init_args;
  init_args.CreateMutex = 0;
}


// From here on, wrap Initialize/Finalize in a fixture.
class InitTest : public ::testing::Test {
protected:
  virtual void SetUp() {
    EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  }
  virtual void TearDown() {
    EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  }
};

TEST_F(InitTest, GetInfo) {
  CK_INFO info = {0};
  EXPECT_CKR_OK(g_fns->C_GetInfo(&info));
  cout << info_description(&info) << endl;
}

TEST_F(InitTest, FailedTermination) {
  EXPECT_EQ(CKR_ARGUMENTS_BAD, g_fns->C_Finalize((void *)1));
}

