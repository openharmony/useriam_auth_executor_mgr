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
#include <message_parcel.h>
#include <string_ex.h>
#include "coauth_hilog_wrapper.h"
#include "query_callback_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void QueryCallbackProxy::OnResult(uint32_t resultCode)
{
    MessageParcel data;
    if (!data.WriteInterfaceToken(QueryCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    if (!data.WriteUint32(resultCode)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(scheduleId).");
        return;
    }
    MessageParcel reply;
    bool ret = SendRequest(static_cast<int32_t>(IQueryCallback::COAUTH_QUERY_RESULT), data, reply);
    if (ret) {
        COAUTH_HILOGI(MODULE_INNERKIT, "ret = %{public}d", ret);
    }
}

bool QueryCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS