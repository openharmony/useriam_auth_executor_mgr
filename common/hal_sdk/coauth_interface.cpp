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

#include "coauth_interface.h"

#include "securec.h"

extern "C" {
#include "coauth_funcs.h"
#include "defines.h"
#include "adaptor_log.h"
#include "lock.h"
}

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
static ExecutorInfo CopyExecutorInfoOut(const ExecutorInfoHal &executorInfoHal)
{
    ExecutorInfo executorInfo;
    executorInfo.authType = executorInfoHal.authType;
    executorInfo.authAbility = executorInfoHal.authAbility;
    executorInfo.esl = executorInfoHal.esl;
    executorInfo.executorType = executorInfoHal.executorType;
    (void)memcpy_s(executorInfo.publicKey, PUBLIC_KEY_LEN, executorInfoHal.pubKey, PUBLIC_KEY_LEN);
    return executorInfo;
}

static ExecutorInfoHal CopyExecutorInfoIn(const ExecutorInfo &executorInfo)
{
    ExecutorInfoHal executorInfoHal;
    executorInfoHal.authType = executorInfo.authType;
    executorInfoHal.authAbility = executorInfo.authAbility;
    executorInfoHal.esl = executorInfo.esl;
    executorInfoHal.executorType = executorInfo.executorType;
    (void)memcpy_s(executorInfoHal.pubKey, PUBLIC_KEY_LEN, executorInfo.publicKey, PUBLIC_KEY_LEN);
    return executorInfoHal;
}

static void CopyScheduleInfoOut(ScheduleInfo &scheduleInfo, const ScheduleInfoHal &scheduleInfoHal)
{
    LOG_INFO("begin");
    scheduleInfo.executors.clear();
    scheduleInfo.authSubType = scheduleInfoHal.authSubType;
    scheduleInfo.templateId = scheduleInfoHal.templateId;
    scheduleInfo.scheduleMode = scheduleInfoHal.scheduleMode;
    for (uint32_t i = 0; i < scheduleInfoHal.executorInfoNum; i++) {
        ExecutorInfo executorInfo = CopyExecutorInfoOut(scheduleInfoHal.executorInfos[i]);
        scheduleInfo.executors.push_back(executorInfo);
    }
}

int32_t GetScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo)
{
    LOG_INFO("begin");
    GlobalLock();
    ScheduleInfoHal scheduleInfoHal;
    int32_t ret = GetScheduleInfo(scheduleId, &scheduleInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule info failed");
        GlobalUnLock();
        return ret;
    }
    CopyScheduleInfoOut(scheduleInfo, scheduleInfoHal);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t DeleteScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo)
{
    LOG_INFO("begin");
    GlobalLock();
    ScheduleInfoHal scheduleInfoHal;
    int32_t ret = GetScheduleInfo(scheduleId, &scheduleInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule info failed");
        (void)RemoveCoAuthSchedule(scheduleId);
        GlobalUnLock();
        return ret;
    }
    CopyScheduleInfoOut(scheduleInfo, scheduleInfoHal);
    (void)RemoveCoAuthSchedule(scheduleId);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

static Buffer *CreateBufferByVector(std::vector<uint8_t> &executorFinishMsg)
{
    LOG_INFO("executorFinishMsg size is %{public}u", executorFinishMsg.size());
    Buffer *data = CreateBufferByData(&executorFinishMsg[0], executorFinishMsg.size());
    return data;
}

int32_t GetScheduleToken(std::vector<uint8_t> executorFinishMsg, ScheduleToken &scheduleToken)
{
    LOG_INFO("begin");
    if (executorFinishMsg.empty()) {
        LOG_ERROR("executorFinishMsg is empty");
        ScheduleInfo scheduleInfo;
        return DeleteScheduleInfo(scheduleToken.scheduleId, scheduleInfo);
    }
    GlobalLock();
    Buffer *executorMsg = CreateBufferByVector(executorFinishMsg);
    if (executorMsg == nullptr) {
        LOG_ERROR("create msg failed");
        GlobalUnLock();
        return RESULT_NO_MEMORY;
    }
    ScheduleTokenHal scheduleTokenHal = {};
    scheduleTokenHal.scheduleId = scheduleToken.scheduleId;
    int32_t ret = ScheduleFinish(executorMsg, &scheduleTokenHal);
    if (ret != RESULT_SUCCESS) {
        GlobalUnLock();
        return ret;
    }
    if (memcpy_s(&scheduleToken, sizeof(ScheduleToken), &scheduleTokenHal, sizeof(ScheduleTokenHal)) != EOK) {
        LOG_ERROR("copy scheduleToken failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t ExecutorRegister(ExecutorInfo executorInfo, uint64_t &executorId)
{
    LOG_INFO("begin");
    GlobalLock();
    ExecutorInfoHal executorInfoHal = CopyExecutorInfoIn(executorInfo);
    int32_t ret = RegisterExecutor(&executorInfoHal, &executorId);
    GlobalUnLock();
    return ret;
}

int32_t ExecutorUnRegister(uint64_t executorId)
{
    LOG_INFO("begin");
    GlobalLock();
    int32_t ret = UnRegisterExecutor(executorId);
    GlobalUnLock();
    return ret;
}

bool IsExecutorExist(uint32_t authType)
{
    LOG_INFO("begin");
    GlobalLock();
    bool ret = IsExecutorExistFunc(authType);
    GlobalUnLock();
    return ret;
}
} // CoAuth
} // UserIAM
} // OHOS