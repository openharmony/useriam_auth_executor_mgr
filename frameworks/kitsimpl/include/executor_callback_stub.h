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

#ifndef EXECUTOR_CALLBACK_STUB_H
#define EXECUTOR_CALLBACK_STUB_H

#include "iexecutor_callback.h"
#include "executor_callback.h"
#include "iremote_stub.h"
namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class ExecutorCallbackStub : public IRemoteStub<IExecutorCallback> {
public:
    ExecutorCallbackStub(const std::shared_ptr<ExecutorCallback>& impl);
    ~ExecutorCallbackStub() override = default;
    virtual void OnMessengerReady(const sptr<IExecutorMessenger> &messenger) override;
    virtual int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                   std::shared_ptr<AuthAttributes> commandAttrs) override;
    virtual int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthAttributes> consumerAttr) override;
    virtual int32_t OnSetProperty(std::shared_ptr<AuthAttributes> properties)  override;
    virtual int32_t OnGetProperty(std::shared_ptr<AuthAttributes> conditions,
                                  std::shared_ptr<AuthAttributes> values) override;
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t OnMessengerReadyStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnBeginExecuteStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnEndExecuteStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnGetPropertyStub(MessageParcel& data, MessageParcel& reply);
    int32_t OnSetPropertyStub(MessageParcel& data, MessageParcel& reply);
    std::shared_ptr<ExecutorCallback> callback_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS
#endif // EXECUTOR_CALLBACK_STUB_H