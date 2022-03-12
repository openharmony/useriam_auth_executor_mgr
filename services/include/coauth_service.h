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

#ifndef COAUTH_SERVICE_H
#define COAUTH_SERVICE_H

#include <system_ability.h>
#include <system_ability_definition.h>

#include "coauth_stub.h"
#include "iset_prop_callback.h"
#include "auth_attributes.h"
#include "coauth_info_define.h"
#include "auth_res_manager.h"
#include "coauth_manager.h"
#include "auth_info.h"
#include "coauth_hilog_wrapper.h"
#include "coauth_errors.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
const int CHECK_TIMES = 3;
const int SLEEP_TIME = 3;
enum class CoAuthRunningState { STATE_STOPPED, STATE_RUNNING };

class CoAuthService : public SystemAbility, public CoAuthStub {
public:
    DECLEAR_SYSTEM_ABILITY(CoAuthService);
    explicit CoAuthService(int32_t systemAbilityId, bool runOnCreate = false);
    virtual ~CoAuthService() override;
    void OnStart() override;
    void OnStop() override;
    virtual uint64_t Register(std::shared_ptr<ResAuthExecutor> executorInfo,
                              const sptr<ResIExecutorCallback> &callback) override;
    virtual void QueryStatus(ResAuthExecutor &executorInfo, const sptr<ResIQueryCallback> &callback) override;
    virtual void BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, const sptr<ICoAuthCallback> &callback) override;
    virtual int32_t Cancel(uint64_t scheduleId) override;
    virtual int32_t GetExecutorProp(ResAuthAttributes &conditions, std::shared_ptr<ResAuthAttributes> values) override;
    virtual void SetExecutorProp(ResAuthAttributes &conditions, const sptr<ISetPropCallback> &callback) override;

private:
    CoAuthRunningState state_ = CoAuthRunningState::STATE_STOPPED;
    AuthResManager authResMgr_;
    CoAuthManager  coAuthMgr_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_SERVICE_H
