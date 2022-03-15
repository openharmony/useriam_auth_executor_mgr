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

#include "executor_messenger.h"
#include "securec.h"
#include "coauth_interface.h"
#include "call_monitor.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
ExecutorMessenger::ExecutorMessenger(UserIAM::CoAuth::AuthResPool* scheduleRes)
{
    ScheResPool_ = scheduleRes;
}

int32_t ExecutorMessenger::SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType,
                                    int32_t dstType, std::shared_ptr<AuthMessage> msg)
{
    if (ScheResPool_ == nullptr || msg == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ or msg is nullptr");
        return FAIL;
    }

    sptr<UserIAM::CoAuth::ICoAuthCallback> callback;
    int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
    if (findRet != SUCCESS || callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheduleCallback not find");
        return FAIL;
    }

    std::vector<uint8_t> message;
    msg->FromUint8Array(message);
    if (message.size() != sizeof(uint32_t)) {
        COAUTH_HILOGE(MODULE_SERVICE, "message size not right");
        return FAIL;
    }

    // trans to acquireCode
    uint32_t acquire = 0;
    if (memcpy_s(&acquire, sizeof(uint32_t), message.data(), message.size()) != EOK) {
        COAUTH_HILOGE(MODULE_SERVICE, "message copy not right");
        return FAIL;
    }
    callback->OnAcquireInfo(acquire);
    COAUTH_HILOGD(MODULE_SERVICE, "feedback acquire info");    
    return SUCCESS;
}

int32_t ExecutorMessenger::DoSignToken(uint64_t scheduleId, std::vector<uint8_t>& scheduleToken,
    std::shared_ptr<AuthAttributes> finalResult, sptr<UserIAM::CoAuth::ICoAuthCallback> callback)
{
    if (ScheResPool_ == nullptr || callback == nullptr) {
        DeleteScheduleInfoById(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ or callback is nullptr");
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_SERVICE, "ExecutorMessenger::DoSignToken");
    UserIAM::CoAuth::ScheduleToken signScheduleToken;
    std::vector<uint8_t> executorFinishMsg;
    signScheduleToken.scheduleId = scheduleId;
    finalResult->GetUint8ArrayValue(AUTH_RESULT, executorFinishMsg);
    int32_t signRet = UserIAM::CoAuth::GetScheduleToken(executorFinishMsg, signScheduleToken);
    if (signRet != SUCCESS) {
        COAUTH_HILOGE(MODULE_SERVICE, "sign token failed, ret is %{public}d", signRet);
        callback->OnFinish(signRet, scheduleToken);
        ScheResPool_->DeleteScheduleCallback(scheduleId);
        return signRet;
    }
    scheduleToken.resize(sizeof(UserIAM::CoAuth::ScheduleToken));
    if (memcpy_s(&scheduleToken[0], scheduleToken.size(), &signScheduleToken,
        sizeof(UserIAM::CoAuth::ScheduleToken)) != EOK) {
        callback->OnFinish(FAIL, scheduleToken);
        ScheResPool_->DeleteScheduleCallback(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "copy scheduleToken failed");
        return FAIL;
    }

    return SUCCESS;
}

int32_t ExecutorMessenger::Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                                  std::shared_ptr<AuthAttributes> finalResult)
{
    COAUTH_HILOGD(MODULE_SERVICE, "ExecutorMessenger::Finish");
    if (ScheResPool_ == nullptr) {
        DeleteScheduleInfoById(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ is nullptr");
        return FAIL;
    }
    uint64_t scheCount;
    ScheResPool_->GetScheduleCount(scheduleId, scheCount);
    if (scheCount > 1) { // The last one will sign the token
        ScheResPool_->ScheduleCountMinus(scheduleId);
        return SUCCESS;
    }
    UserIAM::CoAuth::CallMonitor::GetInstance().MonitorRemoveCall(scheduleId);
    sptr<UserIAM::CoAuth::ICoAuthCallback> callback;
    int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
    if (findRet != SUCCESS || callback == nullptr) {
        DeleteScheduleInfoById(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "get schedule callback fail");
        return FAIL;
    }
    std::vector<uint8_t> scheduleToken;
    if (finalResult == nullptr) {
        DeleteScheduleInfoById(scheduleId);
        callback->OnFinish(FAIL, scheduleToken);
        ScheResPool_->DeleteScheduleCallback(scheduleId);
        COAUTH_HILOGE(MODULE_SERVICE, "finalResult is nullptr");
        return FAIL;
    }

    if (resultCode == SUCCESS) {
        int32_t signRet = DoSignToken(scheduleId, scheduleToken, finalResult, callback);
        if (signRet != SUCCESS) {
            return signRet;
        }
    }
    callback->OnFinish(resultCode, scheduleToken);
    COAUTH_HILOGD(MODULE_SERVICE, "feedback finish info");
    ScheResPool_->DeleteScheduleCallback(scheduleId);
    return SUCCESS;
}

void ExecutorMessenger::DeleteScheduleInfoById(uint64_t scheduleId)
{
    UserIAM::CoAuth::ScheduleInfo scheduleInfo;
    UserIAM::CoAuth::DeleteScheduleInfo(scheduleId, scheduleInfo);
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS