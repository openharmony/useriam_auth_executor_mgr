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
#include <string_ex.h>
#include "coauth_hilog_wrapper.h"
#include "coauth_proxy.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
uint32_t CoAuthProxy::WriteAuthExecutor(AuthResPool::AuthExecutor &executorInfo, MessageParcel &data)
{
    AuthType authType;
    executorInfo.GetAuthType(authType);
    if (!data.WriteInt32(authType)) {
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteInt32,authType:%{public}d", authType);

    uint64_t authAbility;
    executorInfo.GetAuthAbility(authAbility);
    if (!data.WriteUint64(authAbility)) {
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteUint64,authAbility:%{public}" PRIu64, authAbility);

    ExecutorSecureLevel executorSecLevel;
    executorInfo.GetExecutorSecLevel(executorSecLevel);
    if (!data.WriteInt32(executorSecLevel)) {
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteInt32,executorSecLevel:%{public}d", executorSecLevel);

    ExecutorType executorType;
    executorInfo.GetExecutorType(executorType);
    if (!data.WriteInt32(executorType)) {
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteInt32,executorType:%{public}d", executorType);

    std::vector<uint8_t> publicKey;
    executorInfo.GetPublicKey(publicKey);
    if (!data.WriteUInt8Vector(publicKey)) {
        return FAIL;
    }

    std::vector<uint8_t> deviceId;
    executorInfo.GetDeviceId(deviceId);
    if (!data.WriteUInt8Vector(deviceId)) {
        return FAIL;
    }
    return SUCCESS;
}

uint64_t CoAuthProxy::Register(std::shared_ptr<AuthResPool::AuthExecutor> executorInfo,
                               const sptr<AuthResPool::IExecutorCallback> &callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "Register enter");
    if (executorInfo == nullptr || callback == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Register failed, executorInfo or callback is nullptr");
        return 0;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return 0;
    }
    if (WriteAuthExecutor(*executorInfo, data) == FAIL) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write executorInfo failed!");
        return 0;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback).");
        return 0;
    }
    uint64_t result = 0;
    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_EXECUTOR_REGIST), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to SendRequest.");
        return 0;
    }
    if (!reply.ReadUint64(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to ReadUint64.");
        return 0;
    }
    return result;
}

void CoAuthProxy::QueryStatus(AuthResPool::AuthExecutor &executorInfo,
                              const sptr<AuthResPool::IQueryCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    if (WriteAuthExecutor(executorInfo, data) == FAIL) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write executorInfo failed!");
        return;
    }

    if (!data.WriteRemoteObject(callback->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback).");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_QUERY_STATUS), data, reply, false);
    COAUTH_HILOGD(MODULE_INNERKIT, "ret = %{public}d", ret);
}

void CoAuthProxy::BeginSchedule(uint64_t scheduleId, AuthInfo &authInfo, const sptr<ICoAuthCallback> &callback)
{
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }

    std::string GetPkgName;
    authInfo.GetPkgName(GetPkgName);
    if (!data.WriteString(GetPkgName)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "WriteString,GetPkgName failed");
        return;
    }
    uint64_t GetCallerUid;
    authInfo.GetCallerUid(GetCallerUid);
    data.WriteUint64(GetCallerUid);
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteUint64,GetCallerUid:%{public}" PRIu64, GetCallerUid);

    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(scheduleId).");
        return;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "WriteUint64,scheduleId:%{public}" PRIu64, scheduleId);

    if (!data.WriteRemoteObject(callback->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback).");
        return;
    }

    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_SCHEDULE_REQUEST), data, reply, false);
    if (ret) {
        COAUTH_HILOGD(MODULE_INNERKIT, "ret = %{public}d", ret);
    } else {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to SendRequest.");
    }
}

int32_t CoAuthProxy::Cancel(uint64_t scheduleId)
{
    MessageParcel data;
    COAUTH_HILOGD(MODULE_INNERKIT, "CoauthProxy: Cancel enter");
    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }
    if (!data.WriteUint64(scheduleId)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteUint64(scheduleId).");
        return FAIL;
    }

    MessageParcel reply;
    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_SCHEDULE_CANCEL), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %{public}d", ret);
        return FAIL;
    }
    int32_t result = FAIL;
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Read result fail!");
        return FAIL;
    }
    COAUTH_HILOGD(MODULE_INNERKIT, "result = %{public}d", result);
    return result;
}

int32_t CoAuthProxy::GetExecutorProp(AuthResPool::AuthAttributes &conditions,
                                     std::shared_ptr<AuthResPool::AuthAttributes> values)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoauthProxy: GetExecutorProp enter");
    int32_t result = SUCCESS;
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return FAIL;
    }

    if (values == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to get valuesptr.");
        return FAIL;
    }
    std::vector<uint8_t> buffer;
    if (conditions.Pack(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "conditions pack buffer failed!");
        return FAIL;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "data WriteUInt8Vector buffer failed!");
        return FAIL;
    }

    std::vector<uint8_t> valuesReply;
    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_GET_PROPERTY), data, reply);
    if (!ret) {
        COAUTH_HILOGE(MODULE_INNERKIT, "SendRequest is failed, error code: %{public}d", ret);
        return FAIL;
    }
    if (!reply.ReadInt32(result)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Readback fail!");
        return FAIL;
    }
    if (!reply.ReadUInt8Vector(&valuesReply)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "Readback fail!");
        return FAIL;
    } else {
        values->Unpack(valuesReply);
    }
    return result;
}

void CoAuthProxy::SetExecutorProp(AuthResPool::AuthAttributes &conditions,
                                  const sptr<ISetPropCallback> &callback)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoauthProxy: SetExecutorProp enter");
    MessageParcel data;
    MessageParcel reply;

    if (!data.WriteInterfaceToken(CoAuthProxy::GetDescriptor())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "write descriptor failed!");
        return;
    }
    std::vector<uint8_t> buffer;
    if (conditions.Pack(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "conditions pack buffer failed!");
        return;
    }
    if (!data.WriteUInt8Vector(buffer)) {
        COAUTH_HILOGE(MODULE_INNERKIT, "data WriteUInt8Vector buffer failed!");
        return;
    }
    if (!data.WriteRemoteObject(callback->AsObject())) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to WriteRemoteObject(callback).");
        return;
    }
    bool ret = SendRequest(static_cast<int32_t>(ICoAuth::COAUTH_SET_PROPERTY), data, reply, false);
    if (ret) {
        COAUTH_HILOGD(MODULE_INNERKIT, "ret = %{public}d", ret);
    } else {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to SendRequest.");
    }
}

bool CoAuthProxy::SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, bool isSync)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "CoauthProxy: SendRequest enter");
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        COAUTH_HILOGE(MODULE_INNERKIT, "failed to get remote.");
        return false;
    }
    MessageOption option(isSync ? MessageOption::TF_SYNC : MessageOption::TF_ASYNC);
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