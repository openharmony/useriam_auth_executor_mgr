/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#ifndef USER_IAM_COAUTH_INTERFACE
#define USER_IAM_COAUTH_INTERFACE

#include "vector"
#include "common_defines.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
typedef struct {
    uint32_t scheduleResult;
    uint64_t scheduleId;
    uint32_t authType;
    uint64_t authSubType;
    uint64_t templateId;
    uint32_t scheduleMode;
    uint32_t capabilityLevel;
    uint32_t version;
    uint64_t time;
    uint8_t sign[SIGN_LEN];
} ScheduleToken;

typedef struct {
    uint64_t executorId;
    uint32_t authType;
    uint64_t authAbility;
    uint32_t esl;
    uint32_t executorType;
    uint8_t publicKey[PUBLIC_KEY_LEN];
} ExecutorInfo;

typedef struct {
    std::vector<ExecutorInfo> executors;
    uint64_t templateId;
    uint64_t authSubType;
    uint32_t scheduleMode;
} ScheduleInfo;

int32_t GetScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo);
int32_t DeleteScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo);
int32_t GetScheduleToken(std::vector<uint8_t> executorFinishMsg, ScheduleToken &scheduleToken);

int32_t ExecutorRegister(ExecutorInfo executorInfo, uint64_t &executorId);
int32_t ExecutorUnRegister(uint64_t executorId);
bool IsExecutorExist(uint32_t authType);
}
}
}

#endif // USER_IAM_COAUTH_INTERFACE