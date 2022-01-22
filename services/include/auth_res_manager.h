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

#ifndef AUTH_RES_MANAGER_H
#define AUTH_RES_MANAGER_H

#include <iremote_object.h>
#include "auth_res_pool.h"
#include "auth_executor.h"
#include "iexecutor_callback.h"
#include "iquery_callback.h"
#include "coauth_interface.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class AuthResManager {
public:
    uint64_t Register(std::shared_ptr<ResAuthExecutor> executorInfo, sptr<ResIExecutorCallback> callback);
    void QueryStatus(ResAuthExecutor &executorInfo, sptr<ResIQueryCallback> callback);
    int32_t FindExecutorCallback(uint64_t executorID, sptr<ResIExecutorCallback> &callback);
    int32_t FindExecutorCallback(uint32_t authType, sptr<ResIExecutorCallback> &callback);
    int32_t DeleteExecutorCallback(uint64_t executorID);
    int32_t SaveScheduleCallback(uint64_t scheduleId, uint64_t executorNum, sptr<ICoAuthCallback> callback);
    int32_t FindScheduleCallback(uint64_t scheduleId, sptr<ICoAuthCallback> &callback);
    int32_t DeleteScheduleCallback(uint64_t scheduleId);
private:
    class ResIExecutorCallbackDeathRecipient : public IRemoteObject::DeathRecipient {
    public:
        ResIExecutorCallbackDeathRecipient(uint64_t executorID, AuthResManager* parent);
        ~ResIExecutorCallbackDeathRecipient() = default;
        void OnRemoteDied(const wptr<IRemoteObject>& remote) override;

    private:
        uint64_t executorID_;
        AuthResManager* parent_;
        DISALLOW_COPY_AND_MOVE(ResIExecutorCallbackDeathRecipient);
    };
    AuthResPool coAuthResPool_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTH_RES_MANAGER_H
