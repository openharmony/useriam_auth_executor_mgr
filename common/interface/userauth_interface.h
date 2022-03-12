/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef USER_IAM_USERAUTH_INTERFACE
#define USER_IAM_USERAUTH_INTERFACE

#include "vector"
#include "stdint.h"

#include "common_defines.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {
typedef struct {
    uint64_t contextId;
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
} AuthSolution;

typedef struct {
    int32_t authResult;
    uint64_t contextId;
    int32_t userId;
    uint64_t challenge;
    uint32_t authType;
    uint32_t authTrustLevel;
    uint64_t enrolledId;
    uint32_t version;
    uint64_t time;
    uint8_t sign[SIGN_LEN];
} UserAuthToken;

int32_t GenerateSolution(AuthSolution param, std::vector<uint64_t> &scheduleIds);
int32_t RequestAuthResult(uint64_t contextId, std::vector<uint8_t> &scheduleToken, UserAuthToken &authToken,
    std::vector<uint64_t> &scheduleIds);
int32_t CancelContext(uint64_t contextId, std::vector<uint64_t> &scheduleIds);
int32_t GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel);
} // UserAuth
} // UserIAM
} // OHOS

#endif // USER_IAM_USERAUTH_INTERFACE