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
#include <cinttypes>
#include <message_parcel.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_errors.h"
#include "coauth_stub.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
int32_t CoAuthStub::OnRemoteRequest(uint32_t code, MessageParcel &data,
                                    MessageParcel &reply, MessageOption &option)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub::OnRemoteRequest, cmd = %{public}u, flags= %{public}d",
                  code, option.GetFlags());
    std::u16string descripter = CoAuthStub::GetDescriptor();
    std::u16string remoteDescripter = data.ReadInterfaceToken();
    if (descripter != remoteDescripter) {
        COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub::OnRemoteRequest failed, descriptor is not matched!");
        return E_GET_POWER_SERVICE_FAILED;
    }

    switch (code) {
        case static_cast<int32_t>(ICoAuth::COAUTH_EXECUTOR_REGIST):
            return RegisterStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_QUERY_STATUS):
            return QueryStatusStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_SCHEDULE_REQUEST):
            return BeginScheduleStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_SCHEDULE_CANCEL):
            return CancelStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_GET_PROPERTY):
            return GetExecutorPropStub(data, reply);
        case static_cast<int32_t>(ICoAuth::COAUTH_SET_PROPERTY):
            return SetExecutorPropStub(data, reply);
        default:
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
}

void CoAuthStub::ReadAuthExecutor(AuthResPool::AuthExecutor &executorInfo, MessageParcel& data)
{
    int32_t authType = data.ReadInt32();
    executorInfo.SetAuthType(static_cast<AuthType>(authType));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,authType:%{public}d", authType);

    uint64_t authAbility = data.ReadUint64();
    executorInfo.SetAuthAbility(authAbility);
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt64,authAbility:%{public}" PRIu64, authAbility);

    int32_t executorSecLevel = data.ReadInt32();
    executorInfo.SetExecutorSecLevel(static_cast<ExecutorSecureLevel>(executorSecLevel));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,executorSecLevel:%{public}d", executorSecLevel);

    int32_t executorType = data.ReadInt32();
    executorInfo.SetExecutorType(static_cast<ExecutorType>(executorType));
    COAUTH_HILOGD(MODULE_SERVICE, "ReadInt32,executorSecLevel:%{public}d", executorSecLevel);

    std::vector<uint8_t> publicKey;
    data.ReadUInt8Vector(&publicKey);
    executorInfo.SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    data.ReadUInt8Vector(&deviceId);
    executorInfo.SetDeviceId(deviceId);
}

int32_t CoAuthStub::RegisterStub(MessageParcel& data, MessageParcel& reply)
{
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    ReadAuthExecutor(*executorInfo, data);
    sptr<AuthResPool::IExecutorCallback> callback = iface_cast<AuthResPool::IExecutorCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "read IExecutorCallback is nullptr");
        return FAIL;
    }
    uint64_t ret = Register(executorInfo, callback);
    if (!reply.WriteUint64(ret)) {
        COAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t CoAuthStub::QueryStatusStub(MessageParcel& data, MessageParcel& reply)
{
    AuthResPool::AuthExecutor executorInfo;
    ReadAuthExecutor(executorInfo, data);
    sptr<AuthResPool::IQueryCallback> callback = iface_cast<AuthResPool::IQueryCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "read IQueryCallback is nullptr");
        return FAIL;
    }

    QueryStatus(executorInfo, callback);
    return SUCCESS;
}

int32_t CoAuthStub::BeginScheduleStub(MessageParcel& data, MessageParcel& reply)
{
    AuthInfo authInfo;

    std::string GetPkgName = data.ReadString();
    authInfo.SetPkgName(GetPkgName);
    uint64_t GetCallerUid = data.ReadUint64();
    authInfo.SetCallerUid(GetCallerUid);
    COAUTH_HILOGD(MODULE_SERVICE, "ReadUint64,GetCallerUid:%{public}" PRIu64, GetCallerUid);

    uint64_t scheduleId = data.ReadUint64();
    COAUTH_HILOGD(MODULE_SERVICE, "ReadUint64,scheduleId:%{public}" PRIu64, scheduleId);

    sptr<ICoAuthCallback> callback = iface_cast<ICoAuthCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "read ICoAuthCallback is nullptr");
        return FAIL;
    }

    BeginSchedule(scheduleId, authInfo, callback);

    return SUCCESS;
}

int32_t CoAuthStub::CancelStub(MessageParcel& data, MessageParcel& reply)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub: CancelStub enter");

    uint64_t scheduleId = data.ReadUint64();
    COAUTH_HILOGD(MODULE_SERVICE, "ReadUint64 scheduleId:%{public}" PRIu64, scheduleId);

    int ret = Cancel(scheduleId);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(ret)");
        return FAIL;
    }
    return SUCCESS;
}

int32_t CoAuthStub::GetExecutorPropStub(MessageParcel& data, MessageParcel& reply)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub: GetExecutorPropStub enter");
    std::vector<uint8_t> buffer;
    AuthResPool::AuthAttributes conditions;
    data.ReadUInt8Vector(&buffer);
    conditions.Unpack(buffer);
    std::shared_ptr<AuthResPool::AuthAttributes> values = std::make_shared<AuthResPool::AuthAttributes>();
    if (values == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "GetExecutorPropStub failed, values is nullptr");
        return FAIL;
    }

    int32_t ret = GetExecutorProp(conditions, values);
    if (!reply.WriteInt32(ret)) {
        COAUTH_HILOGE(MODULE_SERVICE, "failed to WriteInt32(ret)");
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

int32_t CoAuthStub::SetExecutorPropStub(MessageParcel& data, MessageParcel& reply)
{
    COAUTH_HILOGD(MODULE_SERVICE, "CoAuthStub: SetExecutorPropStub enter");
    std::vector<uint8_t> buffer;
    std::shared_ptr<AuthResPool::AuthAttributes> conditions = std::make_shared<AuthResPool::AuthAttributes>();

    data.ReadUInt8Vector(&buffer);
    conditions->Unpack(buffer);

    sptr<ISetPropCallback> callback = iface_cast<ISetPropCallback>(data.ReadRemoteObject());
    if (callback == nullptr) {
        COAUTH_HILOGE(MODULE_SERVICE, "SetExecutorPropStub failed, callback is nullptr");
        return FAIL;
    }

    SetExecutorProp(*conditions, callback);

    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
