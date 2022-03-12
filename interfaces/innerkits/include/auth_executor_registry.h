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

#ifndef AUTH_EXECUTOR_REGISTRY_H
#define AUTH_EXECUTOR_REGISTRY_H

#include "i_coauth.h"
#include "query_callback.h"
#include "executor_callback.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class AuthExecutorRegistry : public DelayedRefSingleton<AuthExecutorRegistry> {
    DECLARE_DELAYED_REF_SINGLETON(AuthExecutorRegistry);

public:
DISALLOW_COPY_AND_MOVE(AuthExecutorRegistry);
/* InnerKit */
uint64_t Register(std::shared_ptr<AuthExecutor> executorInfo, std::shared_ptr<ExecutorCallback> callback);
void QueryStatus(AuthExecutor &executorInfo, std::shared_ptr<QueryCallback> callback);

private:
    class AuthExecutorRegistryDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        AuthExecutorRegistryDeathRecipient() = default;
        ~AuthExecutorRegistryDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(AuthExecutorRegistryDeathRecipient);
    };
    void ResetProxy(const wptr<IRemoteObject>& remote);
    sptr<CoAuth::ICoAuth> GetProxy();
    std::mutex mutex_;
    sptr<CoAuth::ICoAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // AUTH_EXECUTOR_REGISTRY_H