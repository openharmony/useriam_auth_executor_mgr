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
#include "coauth_funcs.h"

#include "securec.h"

#include "defines.h"
#include "adaptor_log.h"

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

static ScheduleInfo CopyScheduleInfoOut(const ScheduleInfoHal &scheduleInfoHal)
{
    LOG_INFO("begin");
    ScheduleInfo scheduleInfo;
    scheduleInfo.authSubType = scheduleInfoHal.authSubType;
    scheduleInfo.templateId = scheduleInfoHal.templateId;
    scheduleInfo.scheduleMode = scheduleInfoHal.scheduleMode;
    LOG_ERROR("executorInfoNum %{public}d", scheduleInfoHal.executorInfoNum);
    for (int i = 0; i < scheduleInfoHal.executorInfoNum; i++) {
        ExecutorInfo executorInfo = CopyExecutorInfoOut(scheduleInfoHal.executorInfos[i]);
        scheduleInfo.executors.push_back(executorInfo);
    }
    return scheduleInfo;
}

int32_t GetScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo)
{
    LOG_INFO("begin");
    if (!scheduleInfo.executors.empty()) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ScheduleInfoHal scheduleInfoHal;
    int32_t ret = GetScheduleInfo(scheduleId, &scheduleInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule info failed");
        return ret;
    }
    scheduleInfo = CopyScheduleInfoOut(scheduleInfoHal);
    LOG_ERROR("get schedule info schedule = %{public}llu", scheduleInfo.templateId);
    return RESULT_SUCCESS;
}

int32_t DeleteScheduleInfo(uint64_t scheduleId, ScheduleInfo &scheduleInfo)
{
    LOG_INFO("begin");
    if (!scheduleInfo.executors.empty()) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ScheduleInfoHal scheduleInfoHal;
    int32_t ret = GetScheduleInfo(scheduleId, &scheduleInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule info failed");
        return ret;
    }
    scheduleInfo = CopyScheduleInfoOut(scheduleInfoHal);
    (void)RemoveCoAuthSchedule(scheduleId);
    return RESULT_SUCCESS;
}

static Buffer *CreateBufferByVector(std::vector<uint8_t> &executorFinishMsg)
{
    if (executorFinishMsg.empty() || executorFinishMsg.size() == 0) {
        LOG_ERROR("vector is empty");
        LOG_ERROR("size is %{public}u", executorFinishMsg.size());
        return nullptr;
    }
    LOG_INFO("size is %{public}u", executorFinishMsg.size());
    Buffer *data = CreateBufferByData(&executorFinishMsg[0], executorFinishMsg.size());
    return data;
}

int32_t GetScheduleToken(std::vector<uint8_t> executorFinishMsg, ScheduleToken &scheduleToken)
{
    LOG_INFO("begin");
    Buffer *executorMsg = CreateBufferByVector(executorFinishMsg);
    if (executorMsg == nullptr) {
        LOG_ERROR("create msg failed");
        return RESULT_NO_MEMORY;
    }
    ScheduleTokenHal scheduleTokenHal;
    int32_t ret = ScheduleFinish(executorMsg, &scheduleTokenHal);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    if (memcpy_s(&scheduleToken, sizeof(ScheduleToken), &scheduleTokenHal, sizeof(ScheduleTokenHal)) != EOK) {
        LOG_ERROR("copy scheduleToken failed");
        return RESULT_BAD_COPY;
    }
    LOG_INFO("done");
    return RESULT_SUCCESS;
}

int32_t ExecutorRegister(ExecutorInfo executorInfo, uint64_t &executorId)
{
    LOG_INFO("begin");
    ExecutorInfoHal executorInfoHal = CopyExecutorInfoIn(executorInfo);
    LOG_ERROR("authType is %{public}d", executorInfoHal.authType);
    return RegisterExecutor(&executorInfoHal, &executorId);
}

int32_t ExecutorUnRegister(uint64_t executorId)
{
    LOG_INFO("begin");
    return UnRegisterExecutor(executorId);
}

bool IsExecutorExist(uint32_t authType)
{
    LOG_INFO("begin");
    return IsExecutorExistFunc(authType);
}

}
}
}