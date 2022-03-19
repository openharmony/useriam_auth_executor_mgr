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

#include "coauth_manager.h"
#include "inner_event.h"
#include "coauth_thread_pool.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
/* Apply for collaborative scheduling */
void CoAuthManager::BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback)
{
    CoAuthHandle(scheduleId, authInfo, callback);
}

void CoAuthManager::CoAuthHandle(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "schedule callback is null");
        return;
    }
    int32_t executeRet = SUCCESS;
    ScheduleInfo scheduleInfo;
    std::vector<uint8_t> scheduleToken;
    int32_t ret = GetScheduleInfo(scheduleId, scheduleInfo);
    if (ret != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "get schedule info failed");
        return callback->OnFinish(ret, scheduleToken);
    }
    std::size_t executorNum = scheduleInfo.executors.size();
    if (executorNum == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorId does not exist");
        return callback->OnFinish(FAIL, scheduleToken);
    }
    sptr<IRemoteObject::DeathRecipient> dr = new ResICoAuthCallbackDeathRecipient(scheduleId, this);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        COAUTH_HILOGE(MODULE_SERVICE, "add death recipient ResICoAuthCallbackDeathRecipient failed");
    }
    if (coAuthResMgrPtr_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "coAuthResMgrPtr_ is nullptr");
        return callback->OnFinish(FAIL, scheduleToken);
    }
    int32_t saveRet = coAuthResMgrPtr_->SaveScheduleCallback(scheduleId, executorNum, callback);
    if (saveRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "save schedule callback failed");
        return callback->OnFinish(saveRet, scheduleToken);
    }
    OHOS::AppExecFwk::InnerEvent::Callback task = std::bind(&CoAuthManager::TimeOut, this, scheduleId);
    CallMonitor::GetInstance().MonitorCall(delay_time, scheduleId, task);
    BeginExecute(scheduleInfo, executorNum, scheduleId, authInfo, executeRet);

    if (executeRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "there are one or more failures in execution");
        callback->OnFinish(executeRet, scheduleToken);
        coAuthResMgrPtr_->DeleteScheduleCallback(scheduleId);
        CallMonitor::GetInstance().MonitorRemoveCall(scheduleId);
    }
}

void CoAuthManager::BeginExecute(ScheduleInfo &scheduleInfo, std::size_t executorNum, uint64_t scheduleId,
                                 AuthInfo &authInfo, int32_t &executeRet)
{
    executeRet = SUCCESS;
    for (std::size_t i = 0; i < executorNum; i++) {
        uint32_t authType = scheduleInfo.executors[i].authType;
        COAUTH_HILOGD(MODULE_SERVICE, "get authType = %{public}u", authType);
        sptr<ResIExecutorCallback> executorCallback;
        std::vector<uint8_t> publicKey(scheduleInfo.executors[i].publicKey,
                                       scheduleInfo.executors[i].publicKey + PUBLIC_KEY_LEN);
        int32_t findRet = coAuthResMgrPtr_->FindExecutorCallback(authType, executorCallback);
        if ((findRet != SUCCESS) || (executorCallback == nullptr)) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found");
            continue;
        }
        auto commandAttrs = std::make_shared<ResAuthAttributes>();
        SetAuthAttributes(commandAttrs, scheduleInfo, authInfo);
        int32_t ret = executorCallback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
        if (ret != SUCCESS) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor i = %{public}zu failed", i);
            executeRet = ret;
        }
    }
}

void CoAuthManager::SetAuthAttributes(std::shared_ptr<ResAuthAttributes> commandAttrs,
                                      ScheduleInfo &scheduleInfo, AuthInfo &authInfo)
{
    if (commandAttrs == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "commandAttrs is nullptr");
        return;
    }
    std::string callerNameString;
    authInfo.GetPkgName(callerNameString);
    std::vector<uint8_t> callerName;
    callerName.assign(callerNameString.begin(), callerNameString.end());
    uint64_t value;
    authInfo.GetCallerUid(value);
    commandAttrs->SetUint32Value(AUTH_SCHEDULE_MODE, scheduleInfo.scheduleMode);
    commandAttrs->SetUint64Value(AUTH_SUBTYPE, scheduleInfo.authSubType);
    commandAttrs->SetUint64Value(AUTH_TEMPLATE_ID, scheduleInfo.templateId);
    commandAttrs->SetUint64Value(AUTH_CALLER_UID, value);
    commandAttrs->SetUint8ArrayValue(AUTH_CALLER_NAME, callerName);
}

/* Cancel collaborative schedule */
int32_t CoAuthManager::Cancel(uint64_t scheduleId)
{
    int32_t executeRet = SUCCESS;
    ScheduleInfo scheduleInfo;
    sptr<ResIExecutorCallback> callback = nullptr;
    int32_t getRet = GetScheduleInfo(scheduleId, scheduleInfo); // call TA
    if (getRet != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "get shedule info filed");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "cancel is successfull");
    std::size_t executorNum = scheduleInfo.executors.size();
    if (executorNum == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorId does not exist");
        return FAIL;
    }
    for (std::size_t i = 0; i < executorNum; i++) {
        uint32_t authType = scheduleInfo.executors[i].authType;
        sptr<ResIExecutorCallback> executorCallback;
        COAUTH_HILOGD(MODULE_SERVICE, "get exeID = %{public}u", authType);
        int32_t onceRet = coAuthResMgrPtr_->FindExecutorCallback(authType, executorCallback);
        if ((onceRet != 0) || (executorCallback == nullptr)) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found");
            continue;
        }
        auto commandAttrs = std::make_shared<ResAuthAttributes>();
        commandAttrs->SetUint32Value(AUTH_SCHEDULE_MODE, scheduleInfo.scheduleMode);
        commandAttrs->SetUint64Value(AUTH_SUBTYPE, scheduleInfo.authSubType);
        commandAttrs->SetUint64Value(AUTH_TEMPLATE_ID, scheduleInfo.templateId);
        onceRet = executorCallback->OnEndExecute(scheduleId, commandAttrs);
        if (onceRet != SUCCESS) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor i = %{public}zu failed", i);
            executeRet = onceRet;
        }
    }
    if (executeRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "there are one or more failures when canceling");
        return executeRet;
    }
    int32_t deleteRet = DeleteScheduleInfo(scheduleId, scheduleInfo); // call TA
    if (deleteRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "delete schedule info failed, ret = %{public}d", deleteRet);
    }
    return executeRet;
}

/* Set executor properties */
void CoAuthManager::SetExecutorProp(ResAuthAttributes &conditions, sptr<ISetPropCallback> callback)
{
    /*
     * To delete user credential information, the caller must be userauth,
     * The first caller who locks and unlocks the template must be useridm
     */

    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }

    uint32_t result = FAIL;
    sptr<ResIExecutorCallback> execallback = nullptr;
    std::vector<uint8_t> extraInfo;
    uint32_t authType;
    conditions.GetUint32Value(AUTH_TYPE, authType);
    COAUTH_HILOGD(MODULE_SERVICE, "get authType = XXXX%{public}u", authType);
    coAuthResMgrPtr_->FindExecutorCallback(authType, execallback);
    if (execallback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found");
        return callback->OnResult(result, extraInfo);
    }
    std::vector<uint8_t> buffer;
    std::shared_ptr<ResAuthAttributes> properties = std::make_shared<ResAuthAttributes>();
    conditions.Pack(buffer);
    properties->Unpack(buffer);
    result = static_cast<uint32_t>(execallback->OnSetProperty(properties));
    if (result != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "set properties failed");
    }
    callback->OnResult(result, extraInfo);
}

int32_t CoAuthManager::GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values)
{
    int32_t retCode = SUCCESS;
    uint32_t authType;
    sptr<ResIExecutorCallback> execallback = nullptr;
    conditions.GetUint32Value(AUTH_TYPE, authType);
    COAUTH_HILOGD(MODULE_SERVICE, "authType is %{public}u", authType);
    coAuthResMgrPtr_->FindExecutorCallback(authType, execallback);
    if (execallback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found");
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    std::shared_ptr<ResAuthAttributes> properties = std::make_shared<ResAuthAttributes>();
    if (properties == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "properties is nullptr");
        return FAIL;
    }
    conditions.Pack(buffer);
    properties->Unpack(buffer);
    retCode = execallback->OnGetProperty(properties, values);
    if (retCode != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "get properties failed");
    }
    COAUTH_HILOGI(MODULE_SERVICE, "get properties end");
    return retCode;
}

void CoAuthManager::RegistResourceManager(AuthResManager* resMgr)
{
    coAuthResMgrPtr_ = resMgr;
}

CoAuthManager::ResICoAuthCallbackDeathRecipient::ResICoAuthCallbackDeathRecipient(
    uint64_t scheduleId, CoAuthManager* parent) : scheduleId(scheduleId), parent_(parent)
{
}

void CoAuthManager::ResICoAuthCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "remote is nullptr");
        return;
    }
    if (parent_ == nullptr || parent_->coAuthResMgrPtr_) {
        COAUTH_HILOGE(MODULE_SERVICE, "parent or parent coAuthResMgrPtr_ is nullptr");
        return;
    }
    parent_->coAuthResMgrPtr_->DeleteScheduleCallback(scheduleId); 
}

void CoAuthManager::TimeOut(uint64_t scheduleId)
{
    sptr<UserIAM::CoAuth::ICoAuthCallback> callback;
    if (coAuthResMgrPtr_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "coAuthResMgrPtr_ is nullptr");
        return;
    }
    int32_t findRet = coAuthResMgrPtr_->FindScheduleCallback(scheduleId, callback);
    if (findRet != SUCCESS || callback == nullptr) {
        COAUTH_HILOGD(MODULE_SERVICE, "Schedule has ended");
        return;
    }
    std::vector<uint8_t> scheduleToken;
    callback->OnFinish(TIMEOUT, scheduleToken);
    Cancel(scheduleId);
    COAUTH_HILOGW(MODULE_SERVICE, "Schedule timeout");
    coAuthResMgrPtr_->DeleteScheduleCallback(scheduleId);
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
