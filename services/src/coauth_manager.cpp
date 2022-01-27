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

#include "coauth_manager.h"
#include "coauth_thread_pool.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
/* Apply for collaborative scheduling */
void CoAuthManager::coAuth(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback)
{
    CoAuthHandle(scheduleId, authInfo, callback);
}

void CoAuthManager::CoAuthHandle(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "Schedule callback is null.");
        return;
    }
    int32_t executeRet = SUCCESS;
    ScheduleInfo scheduleInfo;
    std::vector<uint8_t> scheduleToken;
    int32_t ret = GetScheduleInfo(scheduleId, scheduleInfo);
    if (ret != SUCCESS) {
        COAUTH_HILOGI(MODULE_SERVICE, "Schedule faild.");
        return callback->OnFinish(ret, scheduleToken);
    }
    std::size_t executorNum = scheduleInfo.executors.size();
    if (executorNum == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorId does not exist.");
        return callback->OnFinish(FAIL, scheduleToken);
    }
    sptr<IRemoteObject::DeathRecipient> dr = new ResICoAuthCallbackDeathRecipient(scheduleId, this);
    if ((!callback->AsObject()->AddDeathRecipient(dr))) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to add death recipient ResICoAuthCallbackDeathRecipient");
    }
    int32_t saveRet = coAuthResMgrPtr_->SaveScheduleCallback(scheduleId, executorNum, callback);
    if (saveRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "Save schedule callback error.");
        return callback->OnFinish(saveRet, scheduleToken);
    }
    for (std::size_t i = 0; i < executorNum; i++) {
        uint32_t authType = scheduleInfo.executors[i].authType;
        COAUTH_HILOGD(MODULE_SERVICE, "get authType = XXXX%{public}04d", authType);
        sptr<ResIExecutorCallback> executorCallback;
        std::vector<uint8_t> publicKey(scheduleInfo.executors[i].publicKey,
                                       scheduleInfo.executors[i].publicKey + PUBLIC_KEY_LEN);
        int32_t findRet = coAuthResMgrPtr_->FindExecutorCallback(authType, executorCallback);
        if ((findRet != SUCCESS) || (executorCallback == nullptr)) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found.");
            continue;
        }
        auto commandAttrs = std::make_shared<ResAuthAttributes>();
        SetAuthAttributes(commandAttrs, scheduleInfo, authInfo);
        executeRet |= executorCallback->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    }
    // set timeout
    if (executeRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "There are one or more failures in execution.");
        return callback->OnFinish(executeRet, scheduleToken);
    }
}

void CoAuthManager::SetAuthAttributes(std::shared_ptr<ResAuthAttributes> commandAttrs,
                                      ScheduleInfo &scheduleInfo, AuthInfo &authInfo)
{
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
    int32_t cancelRet = DeleteScheduleInfo(scheduleId, scheduleInfo); // call TA
    if (cancelRet != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "cancel is failure");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "cancel is sucessfull");
    std::size_t executorNum = scheduleInfo.executors.size();
    if (executorNum == 0) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorId does not exist.");
        return FAIL;
    }
    for (std::size_t i = 0; i < executorNum; i++) {
        uint32_t authType = scheduleInfo.executors[i].authType;
        sptr<ResIExecutorCallback> executorCallback;
        COAUTH_HILOGD(MODULE_SERVICE, "get exeID = XXXX%{public}04d", authType);
        int32_t findRet = coAuthResMgrPtr_->FindExecutorCallback(authType, executorCallback);
        if ((findRet != 0) || (executorCallback == nullptr)) {
            COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found.");
            continue;
        }
        auto commandAttrs = std::make_shared<ResAuthAttributes>();
        commandAttrs->SetUint32Value(AUTH_SCHEDULE_MODE, scheduleInfo.scheduleMode);
        commandAttrs->SetUint64Value(AUTH_SUBTYPE, scheduleInfo.authSubType);
        commandAttrs->SetUint64Value(AUTH_TEMPLATE_ID, scheduleInfo.templateId);
        executeRet |= executorCallback->OnEndExecute(scheduleId, commandAttrs);
    }
    if (executeRet != SUCCESS) {
        COAUTH_HILOGW(MODULE_SERVICE, "There are one or more failures when canceling.");
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
    COAUTH_HILOGD(MODULE_SERVICE, "get authType = XXXX%{public}d", authType);
    coAuthResMgrPtr_->FindExecutorCallback(authType, execallback);
    if (execallback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found.");
        return callback->OnResult(result, extraInfo);
    }
    std::vector<uint8_t> buffer;
    std::shared_ptr<ResAuthAttributes> properties = std::make_shared<ResAuthAttributes>();
    conditions.Pack(buffer);
    properties->Unpack(buffer);
    result = execallback->OnSetProperty(properties);
    if (result != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "set properties failure");
    }
    COAUTH_HILOGI(MODULE_SERVICE, "set properties sucessfull");
    callback->OnResult(result, extraInfo);
}

int32_t CoAuthManager::GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values)
{
    int32_t retCode = SUCCESS;
    uint32_t authType;
    sptr<ResIExecutorCallback> execallback = nullptr;
    conditions.GetUint32Value(AUTH_TYPE, authType);
    COAUTH_HILOGD(MODULE_SERVICE, "authType is %{public}d", authType);
    coAuthResMgrPtr_->FindExecutorCallback(authType, execallback);
    if (execallback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executor callback not found.");
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    std::shared_ptr<ResAuthAttributes> properties = std::make_shared<ResAuthAttributes>();
    conditions.Pack(buffer);
    properties->Unpack(buffer);
    retCode = execallback->OnGetProperty(properties, values);
    if (retCode != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "get properties failure");
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
        COAUTH_HILOGE(MODULE_INNERKIT, "CoAuthCallback OnRemoteDied failed, remote is nullptr");
        return;
    }

    if (parent_ != nullptr) {
        parent_->coAuthResMgrPtr_->DeleteScheduleCallback(scheduleId);
    }
    COAUTH_HILOGE(MODULE_INNERKIT, "ResICoAuthCallbackDeathRecipient::Recv death notice.");
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
