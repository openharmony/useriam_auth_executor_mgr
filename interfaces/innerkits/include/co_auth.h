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

#ifndef CO_AUTH_H
#define CO_AUTH_H

#include <iremote_object.h>
#include <singleton.h>
#include "coauth_callback.h"
#include "set_prop_callback.h"
#include "coauth_info_define.h"
#include "i_coauth.h"
#include "auth_attributes.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuth : public DelayedRefSingleton<CoAuth> {
    DECLARE_DELAYED_REF_SINGLETON(CoAuth);

public:
    DISALLOW_COPY_AND_MOVE(CoAuth);
    void BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, std::shared_ptr<CoAuthCallback> callback);
    int32_t Cancel(uint64_t scheduleId);
    int32_t GetExecutorProp(AuthResPool::AuthAttributes &conditions,
        std::shared_ptr<AuthResPool::AuthAttributes> values);
    void SetExecutorProp(AuthResPool::AuthAttributes &conditions, std::shared_ptr<SetPropCallback> callback);

private:
    class CoAuthDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        CoAuthDeathRecipient() = default;
        ~CoAuthDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        DISALLOW_COPY_AND_MOVE(CoAuthDeathRecipient);
    };

    void ResetProxy(const wptr<IRemoteObject>& remote);
    sptr<ICoAuth> GetProxy();
    std::mutex mutex_;
    sptr<ICoAuth> proxy_ {nullptr};
    sptr<IRemoteObject::DeathRecipient> deathRecipient_ {nullptr};
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // CO_AUTH_H