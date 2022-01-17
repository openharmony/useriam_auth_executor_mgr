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

#ifndef AUTH_EXECUTOR_H
#define AUTH_EXECUTOR_H

#include <vector>
#include <cstdint>
#include <cstdlib>
#include <iremote_broker.h>
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class AuthExecutor {
public:
    AuthExecutor();
    ~AuthExecutor();

    /* Actuator information acquisition */
    int32_t GetAuthType(AuthType &value);                     // Credential type
    int32_t GetAuthAbility(uint64_t &value);                  // Actuator capability
    int32_t GetExecutorSecLevel(ExecutorSecureLevel &value);  // Safety level
    int32_t GetExecutorType(ExecutorType &value);             // Actuator type
    int32_t GetPublicKey(std::vector<uint8_t> &value);        // Public key
    int32_t GetDeviceId(std::vector<uint8_t> &value);         // Device ID

    /* Actuator information setting */
    int32_t SetAuthType(AuthType value);                     // Credential type
    int32_t SetAuthAbility(uint64_t value);                  // Actuator capability
    int32_t SetExecutorSecLevel(ExecutorSecureLevel value);  // Safety level
    int32_t SetExecutorType(ExecutorType value);             // Actuator type
    int32_t SetPublicKey(std::vector<uint8_t> &value);       // Public key
    int32_t SetDeviceId(std::vector<uint8_t> &value);        // Device ID

private:
    AuthType authTypeValue_;
    uint64_t authAbilityValue_;
    ExecutorSecureLevel executorSecLevelValue_;
    ExecutorType executorTypeValue_;
    std::vector<uint8_t> publicKeyValue_;
    std::vector<uint8_t> deviceIdValue_;
};
}  // namespace AuthResPool
}  // namespace userIAM
}  // namespace ohos

#endif  // AUTH_EXECUTOR_H