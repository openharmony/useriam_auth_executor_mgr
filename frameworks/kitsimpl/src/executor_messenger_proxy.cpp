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
#include "executor_messenger_proxy.h"
#include "coauth_hilog_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
int32_t ExecutorMessengerProxy::SendData(uint64_t scheduleId, uint64_t transNum,
                                         int32_t srcType, int32_t dstType, std::shared_ptr<AuthMessage> msg)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t result = 0;
    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }
    if (!data.WriteUint64(scheduleId)) {
        return FAIL;
    }
    if (!data.WriteUint64(transNum)) {
        return FAIL;
    }
    if (!data.WriteInt32(srcType)) {
        return FAIL;
    }
    if (!data.WriteInt32(dstType)) {
        return FAIL;
    }

    std::vector<uint8_t> buffer;
    msg->FromUint8Array(buffer);
    if (!data.WriteUInt8Vector(buffer)) {
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorMessenger::COAUTH_SEND_DATA), data, reply);
    if (ret) {
        result = reply.ReadInt32();
        COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    }
    return result;
}


int32_t ExecutorMessengerProxy::Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                                       std::shared_ptr<AuthAttributes> finalResult)
{
    MessageParcel data;
    MessageParcel reply;
    int32_t result = 0;
    if (!data.WriteInterfaceToken(ExecutorMessengerProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return result;
    }

    if (!data.WriteUint64(scheduleId)) {
        return FAIL;
    }
    if (!data.WriteInt32(srcType)) {
        return FAIL;
    }
    if (!data.WriteInt32(resultCode)) {
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    if (finalResult->Pack(buffer)) {
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorMessenger::COAUTH_FINISH), data, reply);
    if (ret) {
        result = reply.ReadInt32();
        COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    }
    return result;
}
bool ExecutorMessengerProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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
}
}
}