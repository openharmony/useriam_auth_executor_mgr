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

#ifndef USER_IAM_USERIDM_INTERFACE
#define USER_IAM_USERIDM_INTERFACE

#include "vector"
#include "stdint.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace Hal {
typedef struct {
    uint64_t credentialId;
    uint32_t authType;
    uint64_t authSubType;
    uint64_t templateId;
    uint32_t capabilityLevel;
} CredentialInfo;

typedef struct {
    uint32_t authType;
    uint64_t enrolledId;
} EnrolledInfo;

int32_t OpenSession(int32_t userId, uint64_t &challenge);
int32_t CloseSession();
int32_t InitSchedulation(std::vector<uint8_t> authToken, int32_t userId, uint32_t authType, uint64_t authSubType,
    uint64_t &scheduleId);
int32_t DeleteScheduleId(uint64_t &scheduleId);
int32_t AddCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId);
int32_t DeleteCredential(int32_t userId, uint64_t credentialId, std::vector<uint8_t> authToken,
    CredentialInfo &credentialInfo);
int32_t QueryCredential(int32_t userId, uint32_t authType, std::vector<CredentialInfo> &credentialInfos);
int32_t GetSecureUid(int32_t userId, uint64_t &secureUid, std::vector<EnrolledInfo> &enrolledInfos);
int32_t DeleteUser(int32_t userId, std::vector<uint8_t> authToken, std::vector<CredentialInfo> &credentialInfos);
int32_t DeleteUserEnforce(int32_t userId, std::vector<CredentialInfo> &credentialInfos);
int32_t UpdateCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId, CredentialInfo &deletedCredential);
} // Hal
} // UserIDM
} // UserIAM
} // OHOS

#endif // USER_IAM_USERIDM_INTERFACE