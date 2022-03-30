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

#include "call_monitor.h"

#include <cinttypes>

#include "inner_event.h"
#include "event_runner.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
CallMonitor::CallMonitor()
{
    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(true);
    if (runner == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "runner is nullptr");
        return;
    }
    runner->Run();
    eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
}

CallMonitor::~CallMonitor() = default;

void CallMonitor::MonitorCall(int64_t waitTime, uint64_t scheduleId, Callback &timeoutFun)
{
    if (eventHandler_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "eventHandler_ is nullptr");
        return;
    }
    std::string name = std::to_string(scheduleId);
    COAUTH_HILOGI(MODULE_SERVICE,
        "CallMonitor MonitorCall is called, name is 0xXXXX%{public}04" PRIx64, MASK & scheduleId);
    eventHandler_->PostHighPriorityTask(timeoutFun, name, waitTime);
}

void CallMonitor::MonitorRemoveCall(uint64_t scheduleId)
{
    if (eventHandler_ == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "eventHandler_ is nullptr");
        return;
    }
    std::string name = std::to_string(scheduleId);
    COAUTH_HILOGI(MODULE_SERVICE,
        "CallMonitor MonitorRemoveCall is called, name is 0xXXXX%{public}04" PRIx64, MASK & scheduleId);
    eventHandler_->RemoveTask(name);
}
} // namespace PinAuth
} // namespace UserIAM
} // namespace OHOS