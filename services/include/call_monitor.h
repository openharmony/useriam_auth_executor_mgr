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

#ifndef CALL_MONITOR_H
#define CALL_MONITOR_H

#include <stdint.h>
#include <singleton.h>

#include "coauth_hilog_wrapper.h"
#include "event_handler.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
using Callback = OHOS::AppExecFwk::EventHandler::Callback;

class CallMonitor : public DelayedRefSingleton<CallMonitor> {
    DECLARE_DELAYED_REF_SINGLETON(CallMonitor);
public:
    DISALLOW_COPY_AND_MOVE(CallMonitor);

    void MonitorCall(int64_t waitTime, uint64_t scheduleId, Callback &timeoutFun);

    void MonitorRemoveCall(uint64_t scheduleId);
private:
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS

#endif // CALL_MONITOR_H