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

#include "auth_message.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
AuthMessage* AuthMessage::FromUint8Array(std::vector<uint8_t> &msg)
{
    msg = authMessage_;
    return this;
}

AuthMessage::AuthMessage(std::vector<uint8_t> &msg)
{
    authMessage_ = msg;
}

AuthMessage::~AuthMessage() = default;
}  // namespace ohos
}  // namespace userIAM
}  // namespace authResPool