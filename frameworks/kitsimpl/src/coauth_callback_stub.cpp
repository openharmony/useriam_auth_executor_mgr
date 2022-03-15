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

#include "coauth_callback_stub.h"
#include <message_parcel.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
CoAuthCallbackStub::CoAuthCallbackStub(const std::shared_ptr<CoAuthCallback>& impl)
{
    callback_ = impl;
}

int32_t CoAuthCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                            MessageParcel &reply, MessageOption &option)
{
    std::u16string descripter = CoAuthCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGD(MODULE_INNERKIT, "CoAuthStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(ICoAuthCallback::ONFINISH):
            return OnFinishStub(data, reply);
        case static_cast<int32_t>(ICoAuthCallback::ONACQUIREINFO):
            return OnAcquireInfoStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t CoAuthCallbackStub::OnFinishStub(MessageParcel &data, MessageParcel &reply)
{
    uint32_t resultCode = data.ReadUint32();
    std::vector<uint8_t> scheduleToken;
    data.ReadUInt8Vector(&scheduleToken);

    OnFinish(resultCode, scheduleToken);
    return SUCCESS;
}

int32_t CoAuthCallbackStub::OnAcquireInfoStub(MessageParcel &data, MessageParcel &reply)
{
    uint32_t acquire = data.ReadUint32();

    OnAcquireInfo(acquire);
    return SUCCESS;
}

void CoAuthCallbackStub::OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken)
{
    if (callback_ == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "CoAuthCallback is null.");
    } else {
        callback_->OnFinish(resultCode, scheduleToken);
    }
}

void CoAuthCallbackStub::OnAcquireInfo(uint32_t acquire)
{
    if (callback_ == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "CoAuthCallback is null.");
    } else {
        callback_->OnAcquireInfo(acquire);
    }
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS