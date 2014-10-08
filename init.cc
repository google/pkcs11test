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
// PKCS#11 s11.4: General-purpose functions
//   C_Initialize
//   C_Finalize
//   C_GetFunctionList
//   C_GetInfo

#include "pkcs11test.h"

using namespace std;  // So sue me

namespace pkcs11 {
namespace test {

// Explicitly test Initialize/Finalize.
TEST(Init, Simple) {
  EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, Uninitialized) {
  // Nothing should work if the library hasn't been initialized.

  CK_FLAGS flags = CKF_SERIAL_SESSION;
  CK_SESSION_HANDLE session;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED,
             g_fns->C_OpenSession(g_slot_id, flags, NULL_PTR, NULL_PTR, &session));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_CloseSession(1));

  CK_MECHANISM mechanism;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_EncryptInit(1, &mechanism, 1));

  CK_OBJECT_CLASS data_class = CKO_DATA;
  CK_ATTRIBUTE attrs[] = {
    {CKA_CLASS, &data_class, sizeof(data_class)},
  };
  CK_ULONG num_attrs = sizeof(attrs) / sizeof(attrs[0]);
  CK_OBJECT_HANDLE object;
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED,
             g_fns->C_CreateObject(1, attrs, num_attrs, &object));

  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED,
             g_fns->C_FindObjectsInit(1, attrs, num_attrs));
}

TEST(Init, DoubleFinalize) {
  EXPECT_CKR_OK(g_fns->C_Initialize(NULL_PTR));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, UnexpectedFinalize) {
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgsBadReserved) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  // PKCS#11 s11.4: The value of pReserved thereby obtained must be NULL_PTR; it it's not, then C_Initialize should
  // return with the value CKR_ARGUMENTS_BAD.
  init_args.pReserved = (void*)1;
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_Initialize(&init_args));
}

TEST(Init, InitArgsNoNewThreads) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_LIBRARY_CANT_CREATE_OS_THREADS;
  CK_RV rv = g_fns->C_Initialize(&init_args);
  if (rv == CKR_OK) {
    if (g_verbose) cout << "Library can cope without creating OS threads" << endl;
    EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
  } else {
    if (g_verbose) cout << "Library needs to be able to create OS threads" << endl;
    EXPECT_CKR(CKR_NEED_TO_CREATE_THREADS, rv);
  }
}

TEST(Init, InitArgsNoLock) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  EXPECT_CKR_OK(g_fns->C_Initialize(&init_args));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgsInternalLocks) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.flags = CKF_OS_LOCKING_OK;
  // Expect the library to use OS threading primitives
  EXPECT_CKR_OK(g_fns->C_Initialize(&init_args));
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

namespace {
CK_RV MutexCreate(CK_VOID_PTR_PTR ppMutex) {
  return CKR_OK;
}
CK_RV MutexDestroy(CK_VOID_PTR pMutex) {
  return CKR_OK;
}
CK_RV MutexLock(CK_VOID_PTR pMutex) {
  return CKR_OK;
}
CK_RV MutexUnlock(CK_VOID_PTR pMutex) {
  return CKR_OK;
}
}  // namespace

TEST(Init, InitArgsMyLocks) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.CreateMutex = MutexCreate;
  init_args.DestroyMutex = MutexDestroy;
  init_args.LockMutex = MutexLock;
  init_args.UnlockMutex = MutexUnlock;
  CK_RV rv = g_fns->C_Initialize(&init_args);
  if (rv == CKR_CANT_LOCK) {
    TEST_SKIPPED("Application-provided locking functions not supported");
    return;
  }
  EXPECT_CKR_OK(rv);
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

TEST(Init, InitArgsMyOrInternalLocks) {
  CK_C_INITIALIZE_ARGS init_args = {0};
  init_args.CreateMutex = MutexCreate;
  init_args.DestroyMutex = MutexDestroy;
  init_args.LockMutex = MutexLock;
  init_args.UnlockMutex = MutexUnlock;
  init_args.flags = CKF_OS_LOCKING_OK;
  CK_RV rv = g_fns->C_Initialize(&init_args);
  if (rv == CKR_CANT_LOCK) {
    TEST_SKIPPED("Application-provided locking functions not supported");
    return;
  }
  EXPECT_CKR_OK(rv);
  EXPECT_CKR_OK(g_fns->C_Finalize(NULL_PTR));
}

// From here on, wrap Initialize/Finalize in a fixture.
TEST_F(PKCS11Test, InitNestedFail) {
  EXPECT_CKR(CKR_CRYPTOKI_ALREADY_INITIALIZED, g_fns->C_Initialize(NULL_PTR));
}

TEST_F(PKCS11Test, FailedTermination) {
  EXPECT_CKR(CKR_ARGUMENTS_BAD, g_fns->C_Finalize((void *)1));
}

TEST_F(PKCS11Test, GetInfo) {
  CK_INFO info;
  memset(&info, 0, sizeof(info));
  EXPECT_CKR_OK(g_fns->C_GetInfo(&info));
  if (g_verbose) cout << info_description(&info) << endl;
  EXPECT_TRUE(IS_SPACE_PADDED(info.manufacturerID));
  EXPECT_TRUE(IS_SPACE_PADDED(info.libraryDescription));
  EXPECT_LE(2, info.cryptokiVersion.major);
}

TEST_F(PKCS11Test, GetInfoFail) {
  CK_RV rv = g_fns->C_GetInfo(nullptr);
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

TEST(Init, GetInfoNoInit) {
  CK_INFO info;
  memset(&info, 0, sizeof(info));
  EXPECT_CKR(CKR_CRYPTOKI_NOT_INITIALIZED, g_fns->C_GetInfo(&info));
}

TEST_F(PKCS11Test, GetFunctionList) {
  CK_FUNCTION_LIST_PTR fns;
  EXPECT_CKR_OK(g_fns->C_GetFunctionList(&fns));
  EXPECT_EQ(0, memcmp(g_fns, fns, sizeof(CK_FUNCTION_LIST)));
}

TEST_F(PKCS11Test, GetFunctionListFail) {
  CK_RV rv = g_fns->C_GetFunctionList(nullptr) ;
  EXPECT_TRUE(rv == CKR_ARGUMENTS_BAD || rv == CKR_FUNCTION_FAILED) << " rv=" << CK_RV_(rv);
}

}  // namespace test
}  // namespace pkcs11
