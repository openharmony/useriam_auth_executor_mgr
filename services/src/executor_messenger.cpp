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

#include "securec.h"
#include "coauth_interface.h"
#include "executor_messenger.h"

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
    if (ScheResPool_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ is nullptr");
        return FAIL;
    } else {
        sptr<UserIAM::CoAuth::ICoAuthCallback> callback;
        int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
        if (findRet == SUCCESS && callback != nullptr) {
            uint32_t acquire = 0;
            // trans to acquireCode
            callback->OnAcquireInfo(acquire);
            COAUTH_HILOGD(MODULE_SERVICE, "feedback acquire info");
        } else {
            COAUTH_HILOGE(MODULE_SERVICE, "ScheduleCallback not find");
        }
    }
    return SUCCESS;
}
int32_t ExecutorMessenger::Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                                  std::shared_ptr<AuthAttributes> finalResult)
{
    COAUTH_HILOGD(MODULE_SERVICE, "ExecutorMessenger::Finish");
    if (finalResult == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "finalResult is nullptr");
        return FAIL;
    }

    if (ScheResPool_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "ScheResPool_ is nullptr");
        return FAIL;
    } else {
        sptr<UserIAM::CoAuth::ICoAuthCallback> callback;
        uint64_t scheCount;
        ScheResPool_->GetScheduleCount(scheduleId, scheCount);
        if (scheCount > 1) { // The last one will sign the token
            ScheResPool_->ScheduleCountMinus(scheduleId);
            return SUCCESS;
        }
        int32_t findRet = ScheResPool_->FindScheduleCallback(scheduleId, callback);
        if (findRet == SUCCESS && callback != nullptr) {
            UserIAM::CoAuth::ScheduleToken signScheduleToken;
            std::vector<uint8_t> executorFinishMsg;
            std::vector<uint8_t> scheduleToken;
            finalResult->GetUint8ArrayValue(AUTH_RESULT, executorFinishMsg);
            int32_t signRet = UserIAM::CoAuth::GetScheduleToken(executorFinishMsg, signScheduleToken);
            if (signRet != SUCCESS) {
                return signRet;
            }

            scheduleToken.resize(sizeof(UserIAM::CoAuth::ScheduleToken));
            if (memcpy_s(&scheduleToken[0], scheduleToken.size(), &signScheduleToken,
                sizeof(UserIAM::CoAuth::ScheduleToken)) != EOK) {
                COAUTH_HILOGE(MODULE_SERVICE, "copy scheduleToken failed");
                return FAIL;
            }
            callback->OnFinish(resultCode, scheduleToken);
            COAUTH_HILOGD(MODULE_SERVICE, "feedback finish info");
            ScheResPool_->DeleteScheduleCallback(scheduleId);
        } else {
            COAUTH_HILOGE(MODULE_SERVICE, "ScheduleCallback not find");
        }
    }
    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS