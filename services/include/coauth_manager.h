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

#ifndef COAUTH_MANAGER_H
#define COAUTH_MANAGER_H

#include "auth_res_pool.h"
#include "auth_executor.h"
#include "iexecutor_callback.h"
#include "iquery_callback.h"
#include "auth_res_manager.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuthManager {
public:
    void coAuth(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback);
    int32_t Cancel(uint64_t scheduleId);
    int32_t GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values);
    void SetExecutorProp(ResAuthAttributes &conditions, sptr<ISetPropCallback> callback);
    void RegistResourceManager(AuthResManager* resMgr);

    void CoAuthHandle(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback);
private:
    void SetAuthAttributes(std::shared_ptr<ResAuthAttributes> commandAttrs,
                           ScheduleInfo &scheduleInfo, AuthInfo &authInfo);
    class ResICoAuthCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ResICoAuthCallbackDeathRecipient(uint64_t scheduleId, CoAuthManager* parent);
        ~ResICoAuthCallbackDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        uint64_t scheduleId;
        CoAuthManager* parent_;
        DISALLOW_COPY_AND_MOVE(ResICoAuthCallbackDeathRecipient);
    };
    AuthResManager* coAuthResMgrPtr_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_MANAGER_H
