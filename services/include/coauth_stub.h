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

#ifndef COAUTH_STUB_H
#define COAUTH_STUB_H

#include <iremote_stub.h>
#include "co_auth.h"
#include "auth_attributes.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
const std::string PERMISSION_AUTH_RESPOOL = "ohos.permission.ACCESS_AUTH_RESPOOL";
const std::string PERMISSION_ACCESS_COAUTH = "ohos.permission.ACCESS_COAUTH";

class CoAuthStub : public IRemoteStub<ICoAuth> {
public:
    virtual int OnRemoteRequest(
        uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t RegisterStub(MessageParcel& data, MessageParcel& reply);
    int32_t QueryStatusStub(MessageParcel& data, MessageParcel& reply);
    int32_t BeginScheduleStub(MessageParcel &data, MessageParcel &reply);
    int32_t CancelStub(MessageParcel &data, MessageParcel &reply);
    int32_t GetExecutorPropStub(MessageParcel &data, MessageParcel &reply);
    int32_t SetExecutorPropStub(MessageParcel &data, MessageParcel &reply);
    void ReadAuthExecutor(AuthResPool::AuthExecutor &executorInfo, MessageParcel& data);
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_STUB_H