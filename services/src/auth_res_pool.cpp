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
#include <cinttypes>
#include "auth_res_pool.h"
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
int32_t AuthResPool::Insert(uint64_t executorID, std::shared_ptr<ResAuthExecutor> executorInfo,
                            sptr<ResIExecutorCallback> callback)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(authMutex_);
    auto executorRegister = std::make_shared<ExecutorRegister>();
    executorRegister->executorInfo = executorInfo;
    executorRegister->callback = callback;
    authResPool_.insert(std::make_pair(executorID, executorRegister));
    if (authResPool_.begin() != authResPool_.end()) {
        resultCode = SUCCESS;
        COAUTH_HILOGI(MODULE_SERVICE, "authResPool_ insert success");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "authResPool_ is null");
    }
    return resultCode;
}

int32_t AuthResPool::Insert(uint64_t scheduleId, uint64_t executorNum, sptr<ICoAuthCallback> callback)
{
    int32_t resultCode = 0;
    std::lock_guard<std::mutex> lock(scheMutex_);
    auto scheduleRegister = std::make_shared<ScheduleRegister>();
    scheduleRegister->executorNum = executorNum;
    scheduleRegister->callback = callback;
    scheResPool_.insert(std::make_pair(scheduleId, scheduleRegister));
    if (scheResPool_.begin() != scheResPool_.end()) {
        resultCode = SUCCESS;
        COAUTH_HILOGI(MODULE_SERVICE, "scheResPool_ is not null");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "scheResPool_ is null");
    }
    return resultCode;
}

int32_t AuthResPool::FindExecutorCallback(uint64_t executorID, sptr<ResIExecutorCallback> &callback)
{
    int32_t resultCode = 0;
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter = authResPool_.find(executorID);
    if (iter != authResPool_.end()) {
        resultCode = SUCCESS;
        callback = iter->second->callback;
        COAUTH_HILOGI(MODULE_SERVICE, "callback is found");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "callback is not found, size is %{public}u", authResPool_.size());
    }
    return resultCode;
}

int32_t AuthResPool::FindExecutorCallback(uint32_t authType, sptr<ResIExecutorCallback> &callback)
{
    int32_t resultCode = SUCCESS;
    AuthType getAuthType;
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter;
    for (iter = authResPool_.begin(); iter != authResPool_.end(); ++iter) {
        iter->second->executorInfo->GetAuthType(getAuthType);
        if (getAuthType == (int32_t)authType) {
            callback = iter->second->callback;
            COAUTH_HILOGI(MODULE_SERVICE, "Executor callback is found");
            return resultCode;
        }
    }
    COAUTH_HILOGE(MODULE_SERVICE, "Executor callback is not found, size is %{public}u", authResPool_.size());
    callback = nullptr;
    resultCode = FAIL;
    return resultCode;
}

int32_t AuthResPool::DeleteExecutorCallback(uint64_t executorID)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter = authResPool_.find(executorID);
    if (iter != authResPool_.end()) {
        authResPool_.erase(iter);
        resultCode = SUCCESS;
        COAUTH_HILOGI(MODULE_SERVICE, "executor callback XXXX%{public}" PRIx64 " is deleted", executorID);
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "executorID is not found and do not delete callback");
    }
    return resultCode;
}

int32_t AuthResPool::FindScheduleCallback(uint64_t scheduleId, sptr<ICoAuthCallback> &callback)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter != scheResPool_.end()) {
        resultCode = SUCCESS;
        callback = iter->second->callback;
        COAUTH_HILOGI(MODULE_SERVICE, "Schedule callback is found");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "Schedule callback is not found");
    }
    return resultCode;
}

int32_t AuthResPool::ScheduleCountMinus(uint64_t scheduleId)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter != scheResPool_.end()) {
        iter->second->executorNum--;
        resultCode = SUCCESS;
        COAUTH_HILOGD(MODULE_SERVICE, "Schedule callback is found");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "Schedule callback is not found");
    }
    return resultCode;
}

int32_t AuthResPool::GetScheduleCount(uint64_t scheduleId, uint64_t &scheduleCount)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter != scheResPool_.end()) {
        scheduleCount = iter->second->executorNum;
        resultCode = SUCCESS;
        COAUTH_HILOGD(MODULE_SERVICE, "Schedule callback is found");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "Schedule callback is not found");
    }
    return resultCode;
}

int32_t AuthResPool::DeleteScheduleCallback(uint64_t scheduleId)
{
    int32_t resultCode = SUCCESS;
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter != scheResPool_.end()) {
        scheResPool_.erase(iter);
        resultCode = SUCCESS;
        COAUTH_HILOGD(MODULE_SERVICE, "Schedule callback is found");
    } else {
        resultCode = FAIL;
        COAUTH_HILOGE(MODULE_SERVICE, "scheduleId is not found and do not delete callback");
    }
    return resultCode;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS