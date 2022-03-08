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

#include "executor_callback_stub.h"
#include "message_parcel.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
const std::string PERMISSION_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
const std::string PERMISSION_ACCESS_COAUTH = "ohos.permission.ACCESS_COAUTH";

ExecutorCallbackStub::ExecutorCallbackStub(const std::shared_ptr<ExecutorCallback>& impl)
{
    callback_ = impl;
}

int32_t ExecutorCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                              MessageParcel &reply, MessageOption &option)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "ExecutorCallbackStub::OnRemoteRequest!");
    std::u16string descripter = ExecutorCallbackStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGD(MODULE_INNERKIT, "CoAuthStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IExecutorCallback::ON_MESSENGER_READY):
            return OnMessengerReadyStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_BEGIN_EXECUTE):
            return OnBeginExecuteStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_END_EXECUTE):
            return OnEndExecuteStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_SET_PROPERTY):
            return OnSetPropertyStub(data, reply);
        case static_cast<int32_t>(IExecutorCallback::ON_GET_PROPERTY):
            return OnGetPropertyStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

int32_t ExecutorCallbackStub::OnMessengerReadyStub(MessageParcel& data, MessageParcel& reply)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "ExecutorCallbackStub::OnMessengerReadyStub");
    sptr<IExecutorMessenger> messenger = iface_cast<IExecutorMessenger>(data.ReadRemoteObject());
    if (messenger == nullptr) {
        COAUTH_HILOGD(MODULE_INNERKIT, "messenger is nullptr");
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "iface_cast right");
    OnMessengerReady(messenger);
    COAUTH_HILOGD(MODULE_INNERKIT, "OnMessengerReady GetRefPtr");
    return SUCCESS;
}
int32_t ExecutorCallbackStub::OnBeginExecuteStub(MessageParcel& data, MessageParcel& reply)
{
    uint64_t scheduleId = data.ReadUint64();
    std::vector<uint8_t> publicKey, buffer;
    std::shared_ptr<AuthAttributes> commandAttrs = std::make_shared<AuthAttributes>();
    data.ReadUInt8Vector(&publicKey);
    data.ReadUInt8Vector(&buffer);
    commandAttrs->Unpack(buffer);
    int32_t ret = OnBeginExecute(scheduleId, publicKey, commandAttrs);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnEndExecuteStub(MessageParcel& data, MessageParcel& reply)
{
    uint64_t scheduleId = data.ReadUint64();
    std::vector<uint8_t> buffer;
    std::shared_ptr<AuthAttributes> consumerAttr = std::make_shared<AuthAttributes>();
    data.ReadUInt8Vector(&buffer);
    consumerAttr->Unpack(buffer);
    int32_t ret = OnEndExecute(scheduleId, consumerAttr);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorCallbackStub::OnGetPropertyStub(MessageParcel& data, MessageParcel& reply)
{
    std::vector<uint8_t> buffer;
    std::shared_ptr<AuthAttributes> conditions = std::make_shared<AuthAttributes>();
    data.ReadUInt8Vector(&buffer);
    conditions->Unpack(buffer);

    std::shared_ptr<AuthAttributes> values = std::make_shared<AuthAttributes>();
    int32_t ret = OnGetProperty(conditions, values);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }

    std::vector<uint8_t> replyBuffer;
    values->Pack(replyBuffer);
    if (!reply.WriteUInt8Vector(replyBuffer)) {
        COAUTH_HILOGE(MODULE_SERVICE, "failed to replyBuffer");
        return FAIL;
    }
    return SUCCESS;
}
int32_t ExecutorCallbackStub::OnSetPropertyStub(MessageParcel& data, MessageParcel& reply)
{
    std::vector<uint8_t> buffer;
    std::shared_ptr<AuthAttributes> properties = std::make_shared<AuthAttributes>();
    data.ReadUInt8Vector(&buffer);
    properties->Unpack(buffer);

    int32_t ret = OnSetProperty(properties);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

void ExecutorCallbackStub::OnMessengerReady(const sptr<IExecutorMessenger> &messenger)
{
    if (callback_ == nullptr) {
        return;
    } else {
        callback_->OnMessengerReady(messenger);
    }
}
int32_t ExecutorCallbackStub::OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                             std::shared_ptr<AuthAttributes> commandAttrs)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnBeginExecute(scheduleId, publicKey, commandAttrs);
    }
    return ret;
}
int32_t ExecutorCallbackStub::OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnEndExecute(scheduleId, consumerAttr);
    }
    return ret;
}
int32_t ExecutorCallbackStub::OnSetProperty(std::shared_ptr<AuthAttributes> properties)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnSetProperty(properties);
    }
    return ret;
}
int32_t ExecutorCallbackStub::OnGetProperty(std::shared_ptr<AuthAttributes> conditions,
                                            std::shared_ptr<AuthAttributes> values)
{
    int32_t ret = FAIL;
    if (callback_ == nullptr) {
        return FAIL;
    } else {
        ret = callback_->OnGetProperty(conditions, values);
    }
    return ret;
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS