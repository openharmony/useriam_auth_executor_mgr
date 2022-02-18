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

#ifndef AUTH_ATTRIBUTES_H
#define AUTH_ATTRIBUTES_H

#include <vector>
#include <cstdint>
#include <iostream>
#include <map>
#include <algorithm>

#include "coauth_info_define.h"
#include "iremote_object.h"
#include "parcel.h"
#include "iremote_broker.h"
#include "coauth_hilog_wrapper.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
class AuthAttributes {
public:
    AuthAttributes();
    ~AuthAttributes() {};
    void clear();
    int32_t GetBoolValue(AuthAttributeType attrType, bool &value);
    int32_t GetUint32Value(AuthAttributeType attrType, uint32_t &value);
    int32_t GetUint64Value(AuthAttributeType attrType, uint64_t &value);
    int32_t GetUint64ArrayValue(AuthAttributeType attrType, std::vector<uint64_t> &value);
    int32_t GetUint32ArrayValue(AuthAttributeType attrType, std::vector<uint32_t> &value);
    int32_t GetUint8ArrayValue(AuthAttributeType attrType, std::vector<uint8_t> &value);
    int32_t Pack(std::vector<uint8_t> &buffer);

    int32_t SetBoolValue(AuthAttributeType attrType, bool value);
    int32_t SetUint32Value(AuthAttributeType attrType, uint32_t value);
    int32_t SetUint64Value(AuthAttributeType attrType, uint64_t value);
    int32_t SetUint32ArrayValue(AuthAttributeType attrType, std::vector<uint32_t> &value);
    int32_t SetUint64ArrayValue(AuthAttributeType attrType, std::vector<uint64_t> &value);
    int32_t SetUint8ArrayValue(AuthAttributeType attrType, std::vector<uint8_t> &value);
    AuthAttributes* Unpack(std::vector<uint8_t> &buffer);
    enum ValueType {
        BOOLTYPE = 1,
        UINT32TYPE = 2,
        UINT64TYPE = 3,
        UINT32ARRAYTYPE = 4,
        UINT8ARRAYTYPE = 5,
        UINT64ARRAYTYPE = 6
    };
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.UserIAM.AuthResPool.AuthAttributes");

private:
    std::map<AuthAttributeType, bool> boolValueMap_;
    std::map<AuthAttributeType, uint32_t> uint32ValueMap_;
    std::map<AuthAttributeType, uint64_t> uint64ValueMap_;
    std::map<AuthAttributeType, std::vector<uint32_t>> uint32ArraylValueMap_;
    std::map<AuthAttributeType, std::vector<uint64_t>> uint64ArraylValueMap_;
    std::map<AuthAttributeType, std::vector<uint8_t>> uint8ArrayValueMap_;
    std::map<AuthAttributeType, ValueType> authAttributesPosition_;
    std::vector<AuthAttributeType> existAttributes_;
    AuthAttributeType GetUint32FromUint8(std::vector<uint8_t> &data, uint32_t begin);
    bool GetBoolFromUint8(std::vector<uint8_t> &data, uint32_t begin);
    uint64_t  GetUint64FromUint8(std::vector<uint8_t> &data, uint32_t begin);
    std::vector<uint64_t> GetUint64ArrayFromUint8(std::vector<uint8_t> &data, uint32_t begin, uint32_t len);
    std::vector<uint32_t> GetUint32ArrayFromUint8(std::vector<uint8_t> &data, uint32_t begin, uint32_t len);
    void PackToBuffer(std::map<AuthAttributeType, ValueType>::iterator iter,
                      uint32_t dataLength, uint8_t *writePointer,
                      std::vector<uint8_t> &buffer);
    void WriteDataLength(std::vector<uint8_t> &buffer, uint8_t *writePointer, uint32_t dataLength);
    void UnpackTag(AuthAttributeType &tag, std::vector<uint8_t> &buffer,
                   uint32_t &authDataLength, uint32_t &dataLength);
    void Write32Array(std::vector<uint32_t> &uint32ArraylValue, uint8_t *writePointer,
                      std::vector<uint8_t> &buffer);
    void Write64Array(std::vector<uint64_t> &uint64ArraylValue, uint8_t *writePointer,
                      std::vector<uint8_t> &buffer);
};
} // namespace AuthResPool
} // namespace UserIAM
} // namespace OHOS

#endif  // AUTH_ATTRIBUTES_H