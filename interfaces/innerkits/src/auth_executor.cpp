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

#include "auth_executor.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
AuthExecutor::AuthExecutor()
    : authTypeValue_(PIN),
      authAbilityValue_(0),
      executorSecLevelValue_(ESL0),
      executorTypeValue_(TYPE_CO_AUTH),
      publicKeyValue_(0),
      deviceIdValue_(0)
{
}

AuthExecutor::~AuthExecutor()
{
}

int32_t AuthExecutor::GetAuthType(AuthType &value)
{
    value = authTypeValue_;
    return 0;
}
int32_t AuthExecutor::SetAuthType(AuthType value)
{
    authTypeValue_ = value;
    return 0;
}

int32_t AuthExecutor::GetAuthAbility(uint64_t &value)
{
    value = authAbilityValue_;
    return 0;
}
int32_t AuthExecutor::SetAuthAbility(uint64_t value)
{
    authAbilityValue_ = value;
    return 0;
}

int32_t AuthExecutor::GetExecutorSecLevel(ExecutorSecureLevel &value)
{
    value = executorSecLevelValue_;
    return 0;
}
int32_t AuthExecutor::SetExecutorSecLevel(ExecutorSecureLevel value)
{
    executorSecLevelValue_ = value;
    return 0;
}

int32_t AuthExecutor::GetExecutorType(ExecutorType &value)
{
    value = executorTypeValue_;
    return 0;
}
int32_t AuthExecutor::SetExecutorType(ExecutorType value)
{
    executorTypeValue_ = value;
    return 0;
}

int32_t AuthExecutor::GetPublicKey(std::vector<uint8_t> &value)
{
    value = publicKeyValue_;
    return 0;
}
int32_t AuthExecutor::SetPublicKey(std::vector<uint8_t> &value)
{
    publicKeyValue_ = value;
    return 0;
}

int32_t AuthExecutor::GetDeviceId(std::vector<uint8_t> &value)
{
    value = deviceIdValue_;
    return 0;
}
int32_t AuthExecutor::SetDeviceId(std::vector<uint8_t> &value)
{
    deviceIdValue_ = value;
    return 0;
}
}  // namespace ohos
}  // namespace userIAM
}  // namespace authResPool