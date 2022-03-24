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

#ifndef SET_PROP_CALLBACK_PROXY_H
#define SET_PROP_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include "iset_prop_callback.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class SetPropCallbackProxy : public IRemoteProxy<ISetPropCallback> {
public:
    explicit SetPropCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<ISetPropCallback>(impl) {}
    ~SetPropCallbackProxy() override = default;
    void OnResult(uint32_t result, std::vector<uint8_t> &extraInfo) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<SetPropCallbackProxy> delegator_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // SET_PROP_CALLBACK_PROXY_H