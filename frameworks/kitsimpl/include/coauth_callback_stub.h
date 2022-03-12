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

#ifndef COAUTH_CALLBACK_STUB_H
#define COAUTH_CALLBACK_STUB_H

#include <iremote_stub.h>
#include "icoauth_callback.h"
#include "coauth_callback.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuthCallbackStub : public IRemoteStub<ICoAuthCallback> {
public:
    explicit CoAuthCallbackStub(const std::shared_ptr<CoAuthCallback>& impl);
    ~CoAuthCallbackStub() override = default;

    virtual void OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken) override;
    virtual void OnAcquireInfo(uint32_t acquire) override;

    int32_t OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t OnFinishStub(MessageParcel &data, MessageParcel &reply);
    int32_t OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply);

    std::shared_ptr<CoAuthCallback> callback_;
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_CALLBACK_STUB_H