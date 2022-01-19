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

#ifndef IEXECUTOR_MESSENGER_H
#define IEXECUTOR_MESSENGER_H

#include <iremote_broker.h>

#include "coauth_info_define.h"
#include "auth_attributes.h"
#include "auth_message.h"
#include "coauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class IExecutorMessenger : public IRemoteBroker {
public:
    /* Message ID */
    enum {
        COAUTH_SEND_DATA = 0,
        COAUTH_FINISH
    };
    /* Business function */
    virtual int32_t SendData(uint64_t scheduleId, uint64_t transNum, int32_t srcType,
                             int32_t dstType, std::shared_ptr<AuthMessage> msg) = 0;
    virtual int32_t Finish(uint64_t scheduleId, int32_t srcType, int32_t resultCode,
                           std::shared_ptr<AuthAttributes> finalResult) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIAM.AuthResPool.IExecutor_Messenger");
};
} // namespace IExecutor_Messenger
} // namespace UserIAM
} // namespace OHOS
#endif // IEXECUTOR_MESSENGER_H