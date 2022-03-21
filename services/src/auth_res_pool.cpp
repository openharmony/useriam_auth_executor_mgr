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

#include "auth_res_pool.h"
#include <cinttypes>
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
int32_t AuthResPool::Insert(uint64_t executorID, std::shared_ptr<ResAuthExecutor> executorInfo,
                            sptr<ResIExecutorCallback> callback)
{
    std::lock_guard<std::mutex> lock(authMutex_);
    auto executorRegister = std::make_shared<ExecutorRegister>();
    executorRegister->executorInfo = executorInfo;
    executorRegister->callback = callback;
    authResPool_.insert(std::make_pair(executorID, executorRegister));
    if (authResPool_.begin() == authResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "authResPool_ is null");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "authResPool_ insert success");
    return SUCCESS;
}

int32_t AuthResPool::Insert(uint64_t scheduleId, uint64_t executorNum, sptr<ICoAuthCallback> callback)
{
    std::lock_guard<std::mutex> lock(scheMutex_);
    auto scheduleRegister = std::make_shared<ScheduleRegister>();
    scheduleRegister->executorNum = executorNum;
    scheduleRegister->callback = callback;
    scheResPool_.insert(std::make_pair(scheduleId, scheduleRegister));
    if (scheResPool_.begin() == scheResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "scheResPool_ is null");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "scheResPool_ insert success");
    return SUCCESS;
}

int32_t AuthResPool::FindExecutorCallback(uint64_t executorID, sptr<ResIExecutorCallback> &callback)
{
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter = authResPool_.find(executorID);
    if (iter == authResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorID is not found, size is %{public}zu", authResPool_.size());
        return FAIL;
    }
    callback = iter->second->callback;
    COAUTH_HILOGI(MODULE_SERVICE, "find callback by executorID success");
    return SUCCESS;
}

int32_t AuthResPool::FindExecutorCallback(uint32_t authType2Find, sptr<ResIExecutorCallback> &callback)
{
    AuthType authType;
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter;
    for (iter = authResPool_.begin(); iter != authResPool_.end(); ++iter) {
        if (iter->second->executorInfo == nullptr) {
            continue;
        }
        iter->second->executorInfo->GetAuthType(authType);
        if ((AuthType)authType2Find == authType) {
            callback = iter->second->callback;
            COAUTH_HILOGI(MODULE_SERVICE, "find callback by authType success");
            return SUCCESS;
        }
    }
    COAUTH_HILOGE(MODULE_SERVICE, "authType is not found, size is %{public}zu", authResPool_.size());
    callback = nullptr;
    return FAIL;
}

int32_t AuthResPool::DeleteExecutorCallback(uint64_t executorID)
{
    std::lock_guard<std::mutex> lock(authMutex_);
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>>::iterator iter = authResPool_.find(executorID);
    if (iter == authResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorID is not found and delete callback failed");
        return FAIL;
    }
    authResPool_.erase(iter);
    COAUTH_HILOGI(MODULE_SERVICE, "delete executor callback XXXX%{public}" PRIx64 " success", executorID);
    return SUCCESS;
}

int32_t AuthResPool::FindScheduleCallback(uint64_t scheduleId, sptr<ICoAuthCallback> &callback)
{
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter == scheResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "scheduleId is not found and find callback failed");
        return FAIL;
    }
    callback = iter->second->callback;
    COAUTH_HILOGI(MODULE_SERVICE, "find shedule callback success");
    return SUCCESS;
}

int32_t AuthResPool::ScheduleCountMinus(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter == scheResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "scheduleId is not found and count minus one failed");
        return FAIL;
    }
    if (iter->second->executorNum <= 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorNum is less than 1");
        return FAIL;
    }
    iter->second->executorNum--;
    COAUTH_HILOGD(MODULE_SERVICE, "schedule count minus one success");
    return SUCCESS;
}

int32_t AuthResPool::GetScheduleCount(uint64_t scheduleId, uint64_t &scheduleCount)
{
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter == scheResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "scheduleId is not found and get executorNum failed");
        return FAIL;
    }
    scheduleCount = iter->second->executorNum;
    COAUTH_HILOGD(MODULE_SERVICE, "get schedule count success");
    return SUCCESS;
}

int32_t AuthResPool::DeleteScheduleCallback(uint64_t scheduleId)
{
    std::lock_guard<std::mutex> lock(scheMutex_);
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>>::iterator iter = scheResPool_.find(scheduleId);
    if (iter == scheResPool_.end()) {
        COAUTH_HILOGE(MODULE_SERVICE, "scheduleId is not found and delete callback failed");
        return FAIL;
    }
    scheResPool_.erase(iter);
    COAUTH_HILOGD(MODULE_SERVICE, "delete schedule callback success");
    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS