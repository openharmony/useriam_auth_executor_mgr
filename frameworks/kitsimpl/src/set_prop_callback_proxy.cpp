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

#include "set_prop_callback_proxy.h"
#include <message_parcel.h>
#include <string_ex.h>
#include "coauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
void SetPropCallbackProxy::OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(SetPropCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    if (!data.WriteUint32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint32(result).");
        return;
    }

    if (!data.WriteUInt8Vector(extraInfo)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "fail to write WriteUInt8Vector extraInfo");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(ISetPropCallback::ONRESULT), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %{public}d", ret);
    }
}

bool SetPropCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to get remote.");
        return false;
    }
    MessageOption option(MessageOption::TF_SYNC);
    int32_t result = remote->SendRequest(code, data, reply, option);
    if (result != OHOS::NO_ERROR) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to SendRequest.result = %{public}d", result);
        return false;
    }
    return true;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS