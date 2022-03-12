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

#include "executor_messenger_stub.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
const std::string PERMISSION_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
const std::string PERMISSION_ACCESS_COAUTH = "ohos.permission.ACCESS_COAUTH";

int32_t ExecutorMessengerStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                               MessageParcel &reply, MessageOption &option)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub::OnRemoteRequest, cmd = %{public}u, flags= %{public}d",
                  code, option.GetFlags());
    std::u16string descripter = ExecutorMessengerStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGE(MODULE_SERVICE, "CoAuthStub::OnRemoteRequest failed, descriptor is not matched!");
        return FAIL;
    }

    switch (code) {
        case static_cast<int32_t>(IExecutorMessenger::COAUTH_SEND_DATA):
            return SendDataStub(data, reply); // call Stub
        case static_cast<int32_t>(IExecutorMessenger::COAUTH_FINISH):
            return FinishStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}
int32_t ExecutorMessengerStub::SendDataStub(MessageParcel& data, MessageParcel& reply)
{
    uint64_t scheduleId = data.ReadUint64();
    uint64_t transNum = data.ReadUint64();
    int32_t srcType = data.ReadInt32();
    int32_t dstType = data.ReadInt32();
    std::vector<uint8_t> buffer;
    data.ReadUInt8Vector(&buffer);
    std::shared_ptr<AuthMessage> msg = std::make_shared<AuthMessage>(buffer);
    int32_t ret = SendData(scheduleId, transNum, srcType, dstType, msg); // Call business function
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t ExecutorMessengerStub::FinishStub(MessageParcel& data, MessageParcel& reply)
{
    uint64_t scheduleId = data.ReadUint64();
    int32_t srcType = data.ReadInt32();
    int32_t resultCode = data.ReadInt32();

    std::vector<uint8_t> buffer;
    std::shared_ptr<AuthAttributes> finalResult = std::make_shared<AuthAttributes>();
    data.ReadUInt8Vector(&buffer);
    finalResult->Unpack(buffer);

    int32_t ret = Finish(scheduleId, srcType, resultCode, finalResult);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS