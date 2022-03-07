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

#ifndef EXECUTOR_MESSENGER_H
#define EXECUTOR_MESSENGER_H

#include "coauth_info_define.h"
#include "executor_messenger_stub.h"
#include "auth_res_pool.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class ExecutorMessenger : public ExecutorMessengerStub {
public:
    ExecutorMessenger(UserIAM::CoAuth::AuthResPool*);
    ~ExecutorMessenger() override = default;
    virtual int32_t SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType,
                             int32_t dstType, std::shared_ptr<AuthMessage> msg) override;
    virtual int32_t Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                           std::shared_ptr<AuthAttributes> finalResult) override;
private:
    void DeleteScheduleInfoById(uint64_t scheduleId);
    int32_t ExecutorMessenger:: DoSignToken(uint64_t scheduleId, std::vector<uint8_t>& scheduleToken,
    std::shared_ptr<AuthAttributes> finalResult, sptr<UserIAM::CoAuth::ICoAuthCallback> callback);
    UserIAM::CoAuth::AuthResPool* ScheResPool_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // EXECUTOR_MESSENGER_H