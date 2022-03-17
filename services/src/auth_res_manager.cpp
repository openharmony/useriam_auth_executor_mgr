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

#include "auth_res_manager.h"
#include <cinttypes>
#include "executor_messenger.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
/* Register the executor, pass in the executor information and the callback returns the executor ID. */
uint64_t AuthResManager::Register(std::shared_ptr<ResAuthExecutor> executorInfo, sptr<ResIExecutorCallback> callback)
{
    if (executorInfo == nullptr || callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorInfo or callback is nullptr");
        return INVALID_EXECUTOR_ID;
    }
    ExecutorInfo info;
    std::vector<uint8_t> publicKey;
    AuthType authType;
    ExecutorSecureLevel esl;
    ExecutorType exeType;
    executorInfo->GetAuthType(authType);
    executorInfo->GetAuthAbility(info.authAbility);
    executorInfo->GetExecutorSecLevel(esl);
    executorInfo->GetExecutorType(exeType);
    executorInfo->GetPublicKey(publicKey);
    info.authType = authType;
    info.esl = esl;
    info.executorType = exeType;
    if (publicKey.size() > PUBLIC_KEY_LEN) {
        COAUTH_HILOGE(MODULE_SERVICE, "publicKey length too long");
        return INVALID_EXECUTOR_ID;
    }
    for (std::size_t i = 0; i < publicKey.size(); i++) {
        info.publicKey[i] = publicKey[i];
    }

    uint64_t executorId = INVALID_EXECUTOR_ID;
    int32_t result = ExecutorRegister(info, executorId);
    if (result != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "register is failure!");
        return INVALID_EXECUTOR_ID;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new ResIExecutorCallbackDeathRecipient(executorId, this);
    if (!callback->AsObject()->AddDeathRecipient(dr)) {
        COAUTH_HILOGE(MODULE_SERVICE, "Failed to add death recipient ResIExecutorCallbackDeathRecipient");
        return INVALID_EXECUTOR_ID;
    }
    coAuthResPool_.Insert(executorId, executorInfo, callback);
    COAUTH_HILOGI(MODULE_SERVICE, "register is successfull!");
    // Assign messenger
    sptr<UserIAM::AuthResPool::IExecutorMessenger> messenger =
        new UserIAM::AuthResPool::ExecutorMessenger(&coAuthResPool_);
    callback->OnMessengerReady(messenger);
    COAUTH_HILOGD(MODULE_SERVICE, "register is successfull,exeID is XXXX%{public}04" PRIx64, executorId);
    return executorId;
}

/* Query whether the executor is registered */
void AuthResManager::QueryStatus(ResAuthExecutor &executorInfo, sptr<ResIQueryCallback> callback)
{
    bool isExist = false;
    int32_t result = SUCCESS;
    AuthType authType;
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    result = executorInfo.GetAuthType(authType);
    if (result == SUCCESS) {
        COAUTH_HILOGI(MODULE_SERVICE, "GetAuthType is success");
        isExist = IsExecutorExist(authType); // call TA
    } else {
        COAUTH_HILOGE(MODULE_SERVICE, "GetAuthType is failure");
    }
    if (isExist == false) {
        COAUTH_HILOGE(MODULE_SERVICE, "query status executor register is not exist!");
    } else {
        COAUTH_HILOGI(MODULE_SERVICE, "query status executor register is exist!");
    }
    callback->OnResult(isExist ? SUCCESS : FAIL);
}

int32_t AuthResManager::FindExecutorCallback(uint64_t executorID,
                                             sptr<UserIAM::AuthResPool::IExecutorCallback> &callback)
{
    return coAuthResPool_.FindExecutorCallback(executorID, callback);
}

int32_t AuthResManager::FindExecutorCallback(uint32_t authType,
                                             sptr<UserIAM::AuthResPool::IExecutorCallback> &callback)
{
    return coAuthResPool_.FindExecutorCallback(authType, callback);
}

int32_t AuthResManager::DeleteExecutorCallback(uint64_t executorID)
{
    return coAuthResPool_.DeleteExecutorCallback(executorID);
}

int32_t AuthResManager::SaveScheduleCallback(uint64_t scheduleId, uint64_t executorNum, sptr<ICoAuthCallback> callback)
{
    return coAuthResPool_.Insert(scheduleId, executorNum, callback);
}

int32_t AuthResManager::FindScheduleCallback(uint64_t scheduleId, sptr<ICoAuthCallback> &callback)
{
    return coAuthResPool_.FindScheduleCallback(scheduleId, callback);
}

int32_t AuthResManager::DeleteScheduleCallback(uint64_t scheduleId)
{
    return coAuthResPool_.DeleteScheduleCallback(scheduleId);
}

AuthResManager::ResIExecutorCallbackDeathRecipient::ResIExecutorCallbackDeathRecipient(
    uint64_t executorID, AuthResManager* parent) : executorID_(executorID), parent_(parent)
{
}

void AuthResManager::ResIExecutorCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ExecutorCallback OnRemoteDied failed, remote is nullptr");
        return;
    }

    if (parent_ != nullptr) {
        parent_->DeleteExecutorCallback(executorID_);
    }

    int32_t ret = ExecutorUnRegister(executorID_);
    if (ret != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor unregister fail.");
    }
    COAUTH_HILOGW(MODULE_SERVICE, "ResIExecutorCallbackDeathRecipient::Recv death notice.");
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS