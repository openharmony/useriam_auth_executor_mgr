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

#include "set_prop_callback_stub.h"
#include <message_parcel.h>
#include "coauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
SetPropCallbackStub::SetPropCallbackStub(const std::shared_ptr<SetPropCallback>& impl)
{
    callback_ = impl;
}

int32_t SetPropCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply,
    MessageOption &option)
{
    std::u16string descripter = SetPropCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGD(MODULE_INNERKIT, "descriptor is not matched");
        return FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(ISetPropCallback::ONRESULT):
            return OnResultStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t SetPropCallbackStub::OnResultStub(MessageParcel &data, MessageParcel &reply)
{
    uint32_t result = data.ReadUint32();
    std::vector<uint8_t> extraInfo;
    data.ReadUInt8Vector(&extraInfo);

    OnResult(result, extraInfo);

    return SUCCESS;
}

void SetPropCallbackStub::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    if (callback_ == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "callback is null");
    } else {
        callback_->OnResult(result, extraInfo);
    }
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS