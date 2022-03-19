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

#include "co_auth.h"
#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_callback_stub.h"
#include "set_prop_callback_stub.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
CoAuth::CoAuth() = default;
CoAuth::~CoAuth() = default;

sptr<ICoAuth> CoAuth::GetProxy()
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (proxy_ != nullptr) {
        return proxy_;
    }

    sptr<ISystemAbilityManager> sam = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (sam == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "get system ability manager failed");
        return nullptr;
    }
    sptr<IRemoteObject> obj = sam->CheckSystemAbility(SUBSYS_USERIAM_SYS_ABILITY_AUTHEXECUTORMGR);
    if (obj == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "get coauth manager service failed");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new CoAuthDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        COAUTH_HILOGE(MODULE_INNERKIT, "add death recipient failed");
        return nullptr;
    }

    proxy_ = iface_cast<ICoAuth>(obj);
    deathRecipient_ = dr;
    COAUTH_HILOGD(MODULE_INNERKIT, "connect coauth manager service success");
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

void CoAuth::BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, std::shared_ptr<CoAuthCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "BeginSchedule start");
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "BeginSchedule failed, callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "BeginSchedule failed, remote is nullptr");
        return;
    }

    sptr<ICoAuthCallback> icoAuthCallback = new CoAuthCallbackStub(callback);
    if (icoAuthCallback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "BeginSchedule failed, icoAuthCallback is nullptr");
        return;
    }
    return proxy->BeginSchedule(scheduleId, authInfo, icoAuthCallback);
}

int32_t CoAuth::Cancel(uint64_t scheduleId)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth Cancel start");
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
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth: GetExecutorProp start");
    auto proxy = GetProxy();
    if (proxy == nullptr || values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "GetExecutorProp failed, proxy or values is nullptr");
        return FAIL;
    }

    return proxy->GetExecutorProp(conditions, values);
}

void CoAuth::SetExecutorProp(AuthResPool::AuthAttributes &conditions, std::shared_ptr<SetPropCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuth: SetExecutorProp start");
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
    COAUTH_HILOGD(MODULE_INNERKIT, "CoAuthDeathRecipient::Recv death notice.");
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS