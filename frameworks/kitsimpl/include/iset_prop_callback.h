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

#ifndef ISET_PROP_CALLBACK_H
#define ISET_PROP_CALLBACK_H

#include <iremote_broker.h>
#include <iremote_object.h>

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class ISetPropCallback : public IRemoteBroker {
public:

    enum {
        ONRESULT = 0,
    };

    virtual void OnResult(uint32_t result, std::vector<uint8_t> &extraInfo) = 0;

    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.CoAuth.ISetPropCallback");
};
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS
#endif // ISET_PROP_CALLBACK_H
