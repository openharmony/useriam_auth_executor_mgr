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

#ifndef EXECUTOR_CALLBACK_H
#define EXECUTOR_CALLBACK_H

#include "iexecutor_messenger.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class ExecutorCallback {
public:
    virtual void OnMessengerReady(const sptr<IExecutorMessenger> &messenger) = 0;
    virtual int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                   std::shared_ptr<AuthAttributes> commandAttrs) = 0;
    virtual int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr) = 0;
    virtual int32_t OnSetProperty(std::shared_ptr<AuthAttributes> properties)  = 0;
    virtual int32_t OnGetProperty(std::shared_ptr<AuthAttributes> conditions,
                                  std::shared_ptr<AuthAttributes> values) = 0;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS

#endif  // EXECUTOR_CALLBACK_H