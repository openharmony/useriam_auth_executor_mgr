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

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_callback_stub.h"
#include "set_prop_callback_stub.h"
#include "co_auth.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
CoAuth::CoAuth() = default;
CoAuth::~CoAuth() = default;

sptr<ICoAuth> CoAuth::GetProxy()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to get system ability manager");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(COOPERATION_AUTHENTICATION_SERVICE_SA_ID);
    if (obj == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to get coauth manager service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new CoAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<ICoAuth>(obj);
    deathRecipient_ = dr;
    COAUTH_HILOGE(MODULE_INNERKIT, "Succeed to connect coauth manager service");
    return proxy_;
}

void CoAuth::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ == nullptr) {
        return;
    }

    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

void CoAuth::coAuth(uint64_t scheduleId, AuthInfo &authInfo, std::shared_ptr<CoAuthCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "coAuth enter");
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "coAuth failed, callback is nullptr");
        return ;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "coAuth failed, remote is nullptr");
        return;
    }

    sptr<ICoAuthCallback> icoAuthCallback = new CoAuthCallbackStub(callback);
    if (icoAuthCallback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "coAuth failed, icoAuthCallback is nullptr");
        return ;
    }
    return proxy->coAuth(scheduleId, authInfo, icoAuthCallback);
}

int32_t CoAuth::Cancel(uint64_t scheduleId)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth Cancel enter");
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Cancel failed, proxy is nullptr");
        return FAIL;
    }

    return proxy->Cancel(scheduleId);
}

int32_t CoAuth::GetExecutorProp(AuthResPool::AuthAttributes &conditions,
                                std::shared_ptr<AuthResPool::AuthAttributes> values)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth: GetExecutorProp enter");
    auto proxy = GetProxy();
    if (proxy == nullptr || values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "GetExecutorProp failed, proxy or values is nullptr");
        return FAIL;
    }

    return proxy->GetExecutorProp(conditions, values);
}

void CoAuth::SetExecutorProp(AuthResPool::AuthAttributes &conditions, std::shared_ptr<SetPropCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth: SetExecutorProp enter");
    auto proxy = GetProxy();
    if (proxy == nullptr || callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SetExecutorProp failed, proxy or callback is nullptr");
        return;
    }

    sptr<ISetPropCallback> iSetExecutorCallback = new SetPropCallbackStub(callback);
    return proxy->SetExecutorProp(conditions, iSetExecutorCallback);
}


void CoAuth::CoAuthDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    CoAuth::GetInstance().ResetProxy(remote);
    COAUTH_HILOGE(MODULE_INNERKIT, "CoAuthDeathRecipient::Recv death notice.");
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS