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
#include <message_parcel.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_info_define.h"
#include "query_callback_stub.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
QueryCallbackStub::QueryCallbackStub(const std::shared_ptr<QueryCallback>& impl)
{
    callback_ = impl;
}

int32_t QueryCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                           MessageParcel &reply, MessageOption &option)
{
    std::u16string descripter = QueryCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGD(MODULE_INNERKIT, "CoAuthStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }
    switch (code) {
        case static_cast<int32_t>(IQueryCallback::COAUTH_QUERY_RESULT):
            return OnResultStub(data, reply); // call Stub
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t QueryCallbackStub::OnResultStub(MessageParcel& data, MessageParcel& reply)
{
    uint32_t resultCode = data.ReadUint32();
    OnResult(resultCode);

    return SUCCESS;
}

void QueryCallbackStub::OnResult(uint32_t resultCode)
{
    if (callback_ == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "callback_ is null");
    } else {
        callback_->OnResult(resultCode);
    }
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
