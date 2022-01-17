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
#include "query_callback_stub.h"
#include "executor_callback_stub.h"
#include "auth_executor_registry.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
AuthExecutorRegistry::AuthExecutorRegistry() = default;
AuthExecutorRegistry::~AuthExecutorRegistry() = default;

sptr<CoAuth::ICoAuth> AuthExecutorRegistry::GetProxy()
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
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to get coauth service");
        return nullptr;
    }
    sptr<IRemoteObject::DeathRecipient> dr = new AuthExecutorRegistryDeathRecipient();
    if ((obj->IsProxyObject()) && (!obj->AddDeathRecipient(dr))) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Failed to add death recipient");
        return nullptr;
    }

    proxy_ = iface_cast<CoAuth::ICoAuth>(obj);
    deathRecipient_ = dr;
    COAUTH_HILOGI(MODULE_INNERKIT, "Succeed to connect coauth service");
    return proxy_;
}

void AuthExecutorRegistry::ResetProxy(const wptr<IRemoteObject>& remote)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto serviceRemote = proxy_->AsObject();
    if ((serviceRemote != nullptr) && (serviceRemote == remote.promote())) {
        serviceRemote->RemoveDeathRecipient(deathRecipient_);
        proxy_ = nullptr;
    }
}

uint64_t AuthExecutorRegistry::Register(std::shared_ptr<AuthExecutor> executorInfo,
                                        std::shared_ptr<ExecutorCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "Register enter");
    if (executorInfo == nullptr || callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Register failed,executorInfo or callback is nullptr");
        return FAIL;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "GetProxy is nullptr");
        return FAIL;
    }
    sptr<IExecutorCallback> iExecutorCallback = new ExecutorCallbackStub(callback);
    return proxy->Register(executorInfo, iExecutorCallback);
}

void AuthExecutorRegistry::QueryStatus(AuthExecutor &executorInfo, std::shared_ptr<QueryCallback> callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "QueryStatus enter");
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "QueryStatus failed, callback is nullptr");
        return;
    }
    auto proxy = GetProxy();
    if (proxy == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "GetProxy is nullptr");
        return;
    }
    sptr<IQueryCallback> iQueryCallback = new QueryCallbackStub(callback);
    return proxy->QueryStatus(executorInfo, iQueryCallback);
}

void AuthExecutorRegistry::AuthExecutorRegistryDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& remote)
{
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "OnRemoteDied failed, remote is nullptr");
        return;
    }

    AuthExecutorRegistry::GetInstance().ResetProxy(remote);
    COAUTH_HILOGE(MODULE_INNERKIT, "CoAuthDeathRecipient::Recv death notice.");
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS