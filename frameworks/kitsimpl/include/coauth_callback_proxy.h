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

#ifndef COAUTH_CALLBACK_PROXY_H
#define COAUTH_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include <iremote_broker.h>
#include "icoauth_callback.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuthCallbackProxy : public IRemoteProxy<ICoAuthCallback> {
public:
    explicit CoAuthCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ICoAuthCallback>(impl) {}
    ~CoAuthCallbackProxy() override = default;

    void OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken) override;
    void OnAcquireInfo(uint32_t acquire) override;
private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<CoAuthCallbackProxy> delegator_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_CALLBACK_PROXY_H