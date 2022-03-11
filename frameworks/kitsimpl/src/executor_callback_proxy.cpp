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
#include "executor_callback_proxy.h"
#include "coauth_hilog_wrapper.h"
#include "message_parcel.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
void ExecutorCallbackProxy::OnMessengerReady(const sptr<IExecutorMessenger> &messenger)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "ExecutorCallbackProxy OnMessengerReady!");
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }

    if (!data.WriteRemoteObject(messenger.GetRefPtr()->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write RemoteObject failed!");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_MESSENGER_READY), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "ret = %{public}d", ret);
    }
}

int32_t ExecutorCallbackProxy::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                              std::shared_ptr<AuthAttributes> commandAttrs)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write scheduleId failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(publicKey)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write publicKey failed!");
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    if (commandAttrs->Pack(buffer) != SUCCESS) {
        COAUTH_HILOGE(MODULE_INNERKIT, "pack commandAttrs failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed!");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_BEGIN_EXECUTE), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed!");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result failed!");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return SUCCESS;
}

int32_t ExecutorCallbackProxy::OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }

    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write scheduleId failed!");
        return FAIL;
    }

    std::vector<uint8_t> buffer;
    if (consumerAttr->Pack(buffer) != SUCCESS) {
        COAUTH_HILOGE(MODULE_INNERKIT, "pack consumerAttr failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed!");
        return FAIL;
    }

    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_END_EXECUTE), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest fail");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result fail");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnSetProperty(std::shared_ptr<AuthAttributes> properties)
{
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    if (properties->Pack(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "pack properties failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed!");
        return FAIL;
    }
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_SET_PROPERTY), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed!");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result fail");
        return FAIL;
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t ExecutorCallbackProxy::OnGetProperty(std::shared_ptr<AuthAttributes> conditions,
                                             std::shared_ptr<AuthAttributes> values)
{
    MessageParcel data;
    MessageParcel reply;
    if (values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "ExecutorCallbackProxy values is null.");
        return FAIL;
    }

    if (!data.WriteInterfaceToken(ExecutorCallbackProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }

    std::vector<uint8_t> buffer;
    if (conditions->Pack(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "pack conditions failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write buffer failed!");
        return FAIL;
    }

    std::vector<uint8_t> valuesReply;
    bool ret = SendRequest(static_cast<int32_t>(IExecutorCallback::ON_GET_PROPERTY), data, reply); // must sync
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest failed!");
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "read result fail");
        return FAIL;
    }
    if (!reply.ReadUInt8Vector(&valuesReply)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Readback fail!");
        return FAIL;
    } else {
        values->Unpack(valuesReply);
    }
    COAUTH_HILOGI(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}


bool ExecutorCallbackProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply)
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