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

#ifndef COAUTH_MANAGER_H
#define COAUTH_MANAGER_H

#include "auth_res_pool.h"
#include "auth_executor.h"
#include "iexecutor_callback.h"
#include "call_monitor.h"
#include "iquery_callback.h"
#include "auth_res_manager.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
const int64_t delay_time = 300 * 1000;
class CoAuthManager {
public:
    void BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback);
    int32_t Cancel(uint64_t scheduleId);
    int32_t GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values);
    void SetExecutorProp(ResAuthAttributes &conditions, sptr<ISetPropCallback> callback);
    void RegistResourceManager(AuthResManager* resMgr);

    void CoAuthHandle(uint64_t scheduleId, AuthInfo &authInfo, sptr<ICoAuthCallback> callback);
    void TimeOut(uint64_t scheduleId);

private:
    void SetAuthAttributes(std::shared_ptr<ResAuthAttributes> commandAttrs,
        ScheduleInfo &scheduleInfo, AuthInfo &authInfo);
    void BeginExecute(ScheduleInfo &scheduleInfo, std::size_t executorNum, uint64_t scheduleId,
        AuthInfo &authInfo, int32_t &executeRet);
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
    std::shared_ptr<CallMonitor> monitor_ = nullptr;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_MANAGER_H
