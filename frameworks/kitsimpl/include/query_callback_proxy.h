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

#ifndef QUERY_CALLBACK_PROXY_H
#define QUERY_CALLBACK_PROXY_H

#include <iremote_proxy.h>
#include "iquery_callback.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class QueryCallbackProxy : public IRemoteProxy<IQueryCallback> {
public:
    explicit QueryCallbackProxy(const sptr<IRemoteObject>& impl)
        : IRemoteProxy<IQueryCallback>(impl) {}
    ~QueryCallbackProxy() override = default;

    virtual void OnResult(uint32_t resultCode) override;

private:
    bool SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply);

private:
    static inline BrokerDelegator<QueryCallbackProxy> delegator_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // QUERY_CALLBACK_PROXY_H