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

#include "auth_info.h"
#include "coauth_info_define.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
int32_t AuthInfo::GetPkgName(std::string &value)
{
    value = pkgName_;
    return SUCCESS;
}

int32_t AuthInfo::GetCallerUid(uint64_t &value)
{
    value = callerUid_;
    return SUCCESS;
}

int32_t AuthInfo::SetPkgName(std::string value)
{
    pkgName_ = value;
    return SUCCESS;
}

int32_t AuthInfo::SetCallerUid(uint64_t value)
{
    callerUid_ = value;
    return SUCCESS;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
