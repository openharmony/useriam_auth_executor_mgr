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

#ifndef AUTH_MESSAGE_H
#define AUTH_MESSAGE_H

#include <vector>
#include <cstdint>
#include "iremote_object.h"
#include "parcel.h"
#include "iremote_broker.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class AuthMessage {
public:
    AuthMessage(std::vector<uint8_t> &msg);
    ~AuthMessage();
    AuthMessage* FromUint8Array(std::vector<uint8_t> &msg);
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIAM.AuthResPool.AuthMessage");
private:
    std::vector<uint8_t> authMessage_;
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS

#endif  // AUTH_MESSAGE_H