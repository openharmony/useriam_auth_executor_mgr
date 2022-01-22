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

#ifndef AUTH_RES_POOL_H
#define AUTH_RES_POOL_H

#include <mutex>
#include <map>
#include <iterator>
#include <string>
#include "coauth_stub.h"
#include "coauth_errors.h"
#include "coauth_hilog_wrapper.h"
#include "iexecutor_callback.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
    using ResAuthExecutor       = UserIAM::AuthResPool::AuthExecutor;
    using ResIQueryCallback     = UserIAM::AuthResPool::IQueryCallback;
    using ResAuthAttributes     = UserIAM::AuthResPool::AuthAttributes;
    using ResIExecutorCallback  = UserIAM::AuthResPool::IExecutorCallback;

class AuthResPool {
public:
    typedef struct {
        std::shared_ptr<ResAuthExecutor> executorInfo;
        sptr<ResIExecutorCallback> callback;
    } ExecutorRegister;

    typedef struct {
        uint64_t executorNum;
        sptr<ICoAuthCallback> callback;
    } ScheduleRegister;
    int32_t Insert(uint64_t executorID, std::shared_ptr<ResAuthExecutor> executorInfo,
                   sptr<ResIExecutorCallback> callback);
    int32_t Insert(uint64_t scheduleId, uint64_t executorNum, sptr<ICoAuthCallback> callback);
    int32_t FindExecutorCallback(uint64_t executorID, sptr<ResIExecutorCallback> &callback);
    int32_t FindExecutorCallback(uint32_t authType, sptr<ResIExecutorCallback> &callback);
    int32_t DeleteExecutorCallback(uint64_t executorID);
    int32_t FindScheduleCallback(uint64_t scheduleId, sptr<ICoAuthCallback> &callback);
    int32_t ScheduleCountMinus(uint64_t scheduleId);
    int32_t GetScheduleCount(uint64_t scheduleId, uint64_t &scheduleCount);
    int32_t DeleteScheduleCallback(uint64_t scheduleId);

private:
    std::mutex authMutex_;
    std::mutex scheMutex_;
    std::map<uint64_t, std::shared_ptr<ExecutorRegister>> authResPool_;
    std::map<uint64_t, std::shared_ptr<ScheduleRegister>> scheResPool_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // AUTH_RES_POOL_H
