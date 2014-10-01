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
