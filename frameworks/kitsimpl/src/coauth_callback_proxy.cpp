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

#include "coauth_callback_proxy.h"
#include <message_parcel.h>
#include <string_ex.h>
#include "coauth_hilog_wrapper.h"
#include "icoauth_callback.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
void CoAuthCallbackProxy::OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return;
    }
    if (!data.WriteUint32(resultCode)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write resultCode failed");
        return;
    }

    if (!data.WriteUInt8Vector(scheduleToken)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write scheduleToken failed");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(ICoAuthCallback::ONFINISH), data, reply);
    if (ret) {
        COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", ret);
    }
}

void CoAuthCallbackProxy::OnAcquireInfo(uint32_t acquire)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(CoAuthCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed");
        return;
    }
    if (!data.WriteUint32(acquire)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write acquire failed");
        return;
    }

    MessageParcel reply;
    bool ret = SendRequest(static_cast<int32_t>(ICoAuthCallback::ONACQUIREINFO), data, reply);
    if (ret) {
        COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", ret);
    }
}

bool CoAuthCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "get remote failed");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        COAUTH_HILOGE(MODULE_INNERKIT, "send request failed, result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS