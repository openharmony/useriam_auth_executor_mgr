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

#ifndef QUERY_CALLBACK_STUB_H
#define QUERY_CALLBACK_STUB_H

#include <iremote_stub.h>
#include "iquery_callback.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class QueryCallbackStub : public IRemoteStub<IQueryCallback> {
public:
    explicit QueryCallbackStub(const std::shared_ptr<QueryCallback>& impl);
    ~QueryCallbackStub() override = default;

    void OnResult(uint32_t resultCode) override;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t OnResultStub(MessageParcel& data, MessageParcel& reply);

    std::shared_ptr<QueryCallback> callback_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // QUERY_CALLBACK_STUB_H