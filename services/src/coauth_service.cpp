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

#include <file_ex.h>
#include <string_ex.h>
#include <system_ability.h>
#include <system_ability_definition.h>
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <unistd.h>
#include <thread>
#include "useriam_common.h"
#include "coauth_service.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
void CheckSystemAbility()
{
    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to get system ability manager");
        return;
    }
    for (int i = 0; i < CHECK_TIMES; i++) {
        bool isExist = false;
        sam->CheckSystemAbility(PIN_AUTH_SERVICE_SA_ID, isExist);
        if (!isExist) {
            COAUTH_HILOGI(MODULE_INNERKIT, "PIN_AUTH_SERVICE is not exist, start pin auth ability failed, to do next");
        } else {
            COAUTH_HILOGI(MODULE_INNERKIT, "PIN_AUTH_SERVICE is exist, start pin auth ability success");
            return;
        }
        if (i < CHECK_TIMES - 1) {
            sleep(SLEEP_TIME);
        }
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "start pin auth ability all failed");
}

REGISTER_SYSTEM_ABILITY_BY_ID(CoAuthService, COOPERATION_AUTHENTICATION_SERVICE_SA_ID, true);
CoAuthService::CoAuthService(int32_t systemAbilityId, bool runOnCreate)
    : SystemAbility(systemAbilityId, runOnCreate)
{
    coAuthMgr_.RegistResourceManager(&authResMgr_);
}

CoAuthService::~CoAuthService()
{
}

void CoAuthService::OnStart()
{
    if (state_ == CoAuthRunningState::STATE_RUNNING) {
        COAUTH_HILOGW(MODULE_SERVICE, "CoAuthService has already started");
        return;
    }
    COAUTH_HILOGI(MODULE_SERVICE, "Start service");
    if (!Publish(this)) {
        COAUTH_HILOGE(MODULE_SERVICE, "Failed to publish service");
        return;
    }
    state_ = CoAuthRunningState::STATE_RUNNING;

    if (!Common::IsIAMInited()) {
        if (Common::Init() != SUCCESS) {
            COAUTH_HILOGI(MODULE_SERVICE, " IAM CA init failed");
        }
        COAUTH_HILOGI(MODULE_SERVICE, " IAM CA init success");
    } else {
        COAUTH_HILOGI(MODULE_SERVICE, " IAM CA is inited");
    }

    // Send registration broadcast
    // Start other sevice
    std::thread checkThread(OHOS::UserIAM::CoAuth::CheckSystemAbility);
    checkThread.join();
}

void CoAuthService::OnStop()
{
    if (state_ == CoAuthRunningState::STATE_STOPPED) {
        COAUTH_HILOGW(MODULE_SERVICE, "CoAuthService already stopped");
        return;
    }
    state_ = CoAuthRunningState::STATE_STOPPED;

    if (Common::IsIAMInited()) {
        if (Common::Close() != SUCCESS) {
            COAUTH_HILOGI(MODULE_SERVICE, " IAM CA Close failed");
        }
        COAUTH_HILOGI(MODULE_SERVICE, " IAM CA close success");
    } else {
        COAUTH_HILOGI(MODULE_SERVICE, " IAM CA is closed");
    }
    COAUTH_HILOGI(MODULE_SERVICE, "Stop service");
}

/* Register the executor, pass in the executor information and the callback returns the executor ID. */
uint64_t CoAuthService::Register(std::shared_ptr<ResAuthExecutor> executorInfo,
                                 const sptr<ResIExecutorCallback> &callback)
{
    if (executorInfo == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "executorInfo is nullptr");
        return FAIL;
    }

    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return FAIL;
    }

    uint64_t exeID = authResMgr_.Register(executorInfo, callback);
    COAUTH_HILOGE(MODULE_SERVICE, "exeID is XXXX%{public}04llx", exeID);
    return exeID;
}

/* Query whether the executor is registered */
void CoAuthService::QueryStatus(ResAuthExecutor &executorInfo, const sptr<ResIQueryCallback> &callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    return authResMgr_.QueryStatus(executorInfo, callback);
}

/* Apply for collaborative scheduling */
void CoAuthService::coAuth(uint64_t scheduleId, AuthInfo &authInfo, const sptr<ICoAuthCallback> &callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    return coAuthMgr_.coAuth(scheduleId, authInfo, callback);
}

/* Cancel collaborative schedule */
int32_t CoAuthService::Cancel(uint64_t scheduleId)
{
    return coAuthMgr_.Cancel(scheduleId);
}

/* Set executor properties */
void CoAuthService::SetExecutorProp(ResAuthAttributes &conditions, const sptr<ISetPropCallback> &callback)
{
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "callback is nullptr");
        return;
    }
    return coAuthMgr_.SetExecutorProp(conditions, callback);
}

/* Get executor properties */
int32_t CoAuthService::GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values)
{
    if (values == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "values pointer is nullptr");
        return FAIL;
    }
    return coAuthMgr_.GetExecutorProp(conditions, values);
}
} // namespace CoAu
} // namespace UserIAM
} // namespace OHOS
