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

#include "auth_attributes.h"

namespace OHOS {
namespace UserIAM {
namespace AuthResPool {
AuthAttributes::AuthAttributes()
{
    InsertMap(AUTH_RESULT_CODE, UINT32TYPE);
    InsertMap(AUTH_SIGNATURE, UINT8ARRAYTYPE);
    InsertMap(AUTH_IDENTIFY_MODE, UINT32TYPE);
    InsertMap(AUTH_TEMPLATE_ID, UINT64TYPE);
    InsertMap(AUTH_TEMPLATE_ID_LIST, UINT64ARRAYTYPE);
    InsertMap(AUTH_REMAIN_COUNT, UINT32TYPE);
    InsertMap(AUTH_REMAIN_TIME, UINT32TYPE);
    InsertMap(AUTH_SESSION_ID, UINT64TYPE);
    InsertMap(AUTH_CALLER_NAME, UINT8ARRAYTYPE);
    InsertMap(AUTH_SCHEDULE_VERSION, UINT32TYPE);
    InsertMap(AUTH_LOCK_OUT_TEMPLATE, UINT64TYPE);
    InsertMap(AUTH_UNLOCK_TEMPLATE, UINT64TYPE);
    InsertMap(AUTH_SUBTYPE, UINT64TYPE);
    InsertMap(AUTH_SCHEDULE_MODE, UINT32TYPE);
    InsertMap(AUTH_PROPERTY_MODE, UINT32TYPE);
    InsertMap(AUTH_TYPE, UINT32TYPE);
    InsertMap(AUTH_CREDENTIAL_ID, UINT64TYPE);
    InsertMap(AUTH_CONTROLLER, BOOLTYPE);
    InsertMap(AUTH_CALLER_UID, UINT64TYPE);
    InsertMap(AUTH_RESULT, UINT8ARRAYTYPE);
    InsertMap(ALGORITHM_INFO, UINT8ARRAYTYPE);
}

void AuthAttributes::clear()
{
    boolValueMap_.clear();
    uint32ValueMap_.clear();
    uint64ValueMap_.clear();
    uint32ArraylValueMap_.clear();
    uint64ArraylValueMap_.clear();
    uint8ArrayValueMap_.clear();
}

int32_t AuthAttributes::GetBoolValue(AuthAttributeType attrType, bool &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, bool>::iterator iter = boolValueMap_.find(attrType);
    if (iter != boolValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::GetUint32Value(AuthAttributeType attrType, uint32_t &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, uint32_t>::iterator iter = uint32ValueMap_.find(attrType);
    if (iter != uint32ValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::GetUint64Value(AuthAttributeType attrType, uint64_t &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, uint64_t>::iterator iter = uint64ValueMap_.find(attrType);
    if (iter != uint64ValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::GetUint32ArrayValue(AuthAttributeType attrType, std::vector<uint32_t> &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, std::vector<uint32_t> >::iterator iter = uint32ArraylValueMap_.find(attrType);
    if (iter != uint32ArraylValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::GetUint64ArrayValue(AuthAttributeType attrType, std::vector<uint64_t> &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, std::vector<uint64_t> >::iterator iter = uint64ArraylValueMap_.find(attrType);
    if (iter != uint64ArraylValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::GetUint8ArrayValue(AuthAttributeType attrType, std::vector<uint8_t> &value)
{
    int32_t ret = SUCCESS;
    std::map<AuthAttributeType, std::vector<uint8_t> >::iterator iter = uint8ArrayValueMap_.find(attrType);
    if (iter != uint8ArrayValueMap_.end()) {
        value = iter->second;
    } else {
        ret = FAIL;
    }
    return ret;
}

int32_t AuthAttributes::SetBoolValue(AuthAttributeType attrType, bool value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != BOOLTYPE) {
        return FAIL;
    }
    boolValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    return ret;
}

int32_t AuthAttributes::SetUint32Value(AuthAttributeType attrType, uint32_t value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != UINT32TYPE) {
        return FAIL;
    }
    uint32ValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    COAUTH_HILOGD(MODULE_INNERKIT, "SetUint32Value : %{public}d.", value);
    return ret;
}

int32_t AuthAttributes::SetUint64Value(AuthAttributeType attrType, uint64_t value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != UINT64TYPE) {
        return FAIL;
    }
    uint64ValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    return ret;
}

int32_t AuthAttributes::SetUint32ArrayValue(AuthAttributeType attrType, std::vector<uint32_t> &value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != UINT32ARRAYTYPE) {
        return FAIL;
    }
    uint32ArraylValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    return ret;
}

int32_t AuthAttributes::SetUint64ArrayValue(AuthAttributeType attrType, std::vector<uint64_t> &value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != UINT64ARRAYTYPE) {
        return FAIL;
    }
    uint64ArraylValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    return ret;
}

int32_t AuthAttributes::SetUint8ArrayValue(AuthAttributeType attrType, std::vector<uint8_t> &value)
{
    int32_t ret = SUCCESS;
    if (authAttributesPosition_[attrType] != UINT8ARRAYTYPE) {
        return FAIL;
    }
    uint8ArrayValueMap_[attrType] = value;
    existAttributes_.push_back(attrType);
    return ret;
}

void AuthAttributes::UnpackTag(AuthAttributeType &tag, std::vector<uint8_t> &buffer,
                               uint32_t &authDataLength, uint32_t &dataLength)
{
    tag = GetUint32FromUint8(buffer, authDataLength);
    authDataLength += sizeof(uint32_t);
    dataLength = static_cast<uint32_t >(GetUint32FromUint8(buffer, authDataLength));
    authDataLength += sizeof(uint32_t);
}

AuthAttributes* AuthAttributes::Unpack(std::vector<uint8_t> &buffer)
{
    if (buffer.size() == 0) {
        return nullptr;
    }
    uint32_t dataLength, authDataLength = 0;
    AuthAttributeType tag;
    std::vector<uint32_t> uint32ArraylValue;
    std::vector<uint64_t> uint64ArraylValue;
    std::vector<uint8_t> uint8ArrayValue;
    UnpackTag(tag, buffer, authDataLength, dataLength);
    UnpackTag(tag, buffer, authDataLength, dataLength);
    while (authDataLength < buffer.size()) {
        UnpackTag(tag, buffer, authDataLength, dataLength);
        std::map<AuthAttributeType, ValueType>::iterator iter = authAttributesPosition_.find(tag);
        switch (iter->second) {
            case BOOLTYPE:
                SetBoolValue(tag, GetBoolFromUint8(buffer, authDataLength));
                authDataLength += sizeof(bool);
                break;
            case UINT32TYPE:
                SetUint32Value(tag, static_cast<uint32_t>(GetUint32FromUint8(buffer, authDataLength)));
                authDataLength += sizeof(uint32_t);
                break;
            case UINT64TYPE:
                SetUint64Value(tag, GetUint64FromUint8(buffer, authDataLength));
                authDataLength += sizeof(uint64_t);
                break;
            case UINT32ARRAYTYPE:
                uint32ArraylValue = GetUint32ArrayFromUint8(buffer, authDataLength, dataLength);
                SetUint32ArrayValue(tag, uint32ArraylValue);
                authDataLength += dataLength;
                break;
            case UINT64ARRAYTYPE:
                uint64ArraylValue = GetUint64ArrayFromUint8(buffer, authDataLength, dataLength);
                SetUint64ArrayValue(tag, uint64ArraylValue);
                authDataLength += dataLength;
                break;
            case UINT8ARRAYTYPE:
                if (dataLength != 0) {
                    uint8ArrayValue.insert(uint8ArrayValue.begin(), buffer.begin() + authDataLength,
                                           buffer.begin() + authDataLength + dataLength);
                    SetUint8ArrayValue(tag, uint8ArrayValue);
                    authDataLength += dataLength;
                }
                break;
            default:
                break;
        }
    }
    return this;
}

AuthAttributeType AuthAttributes::GetUint32FromUint8(std::vector<uint8_t> &data, uint32_t begin)
{
    uint8_t tmp[sizeof(uint32_t)];
    for (uint32_t i = 0; i < sizeof(uint32_t); i++) {
        tmp[i] = data[begin + i];
    }
    AuthAttributeType *re = static_cast<AuthAttributeType *>(static_cast<void *>(tmp));
    return *re;
}

bool AuthAttributes::GetBoolFromUint8(std::vector<uint8_t> &data, uint32_t begin)
{
    uint8_t tmp = data[begin];
    bool *re = static_cast<bool *>(static_cast<void *>(&tmp));
    return *re;
}

uint64_t AuthAttributes::GetUint64FromUint8(std::vector<uint8_t> &data, uint32_t begin)
{
    uint8_t tmp[sizeof(uint64_t)];
    for (uint32_t i = 0; i < sizeof(uint64_t); i++) {
        tmp[i] = data[begin + i];
    }
    uint64_t *re = static_cast<uint64_t *>(static_cast<void *>(tmp));
    return *re;
}

std::vector<uint32_t> AuthAttributes::GetUint32ArrayFromUint8(std::vector<uint8_t> &data, uint32_t begin, uint32_t len)
{
    std::vector<uint32_t> tmp;
    for (uint32_t i = 0; i < len / sizeof(uint32_t); i++) {
        uint32_t uint32data = GetUint32FromUint8(data, begin + i * sizeof(uint32_t));
        tmp.push_back(uint32data);
        COAUTH_HILOGD(MODULE_INNERKIT, "buffer read uint32ArrayValue : %{public}d.", uint32data);
    }
    return tmp;
}

std::vector<uint64_t> AuthAttributes::GetUint64ArrayFromUint8(std::vector<uint8_t> &data, uint32_t begin, uint32_t len)
{
    std::vector<uint64_t> tmp;
    for (uint32_t i = 0; i < len / sizeof(uint64_t); i++) {
        uint64_t uint64data = GetUint64FromUint8(data, begin + i * sizeof(uint64_t));
        tmp.push_back(uint64data);
        COAUTH_HILOGD(MODULE_INNERKIT, "buffer read uint64ArrayValue : %{public}llu.", uint64data);
    }
    return tmp;
}

int32_t AuthAttributes::Pack(std::vector<uint8_t> &buffer)
{
    uint8_t *writePointer;
    uint32_t dataLength = 0, tag, authDataLength = 0;

    buffer.clear();

    sort(existAttributes_.begin(), existAttributes_.end());
    for (int32_t i = 0; i != existAttributes_.size(); i++) {
        if (existAttributes_[i] == AUTH_ROOT ||
            existAttributes_[i] == AUTH_DATA ||
            existAttributes_[i] == AUTH_SIGNATURE) {
            continue;
        }
        tag = authAttributesPosition_.find(existAttributes_[i])->first;
        writePointer = static_cast<uint8_t*>(static_cast<void *>(&tag));
        buffer.insert(buffer.end(), writePointer, writePointer + sizeof(AuthAttributeType));
        COAUTH_HILOGD(MODULE_INNERKIT, "data Write tag : %{public}d.", tag);
        PackToBuffer(authAttributesPosition_.find(existAttributes_[i]), dataLength, writePointer, buffer);
    }

    authDataLength = buffer.size();
    writePointer = static_cast<uint8_t*>(static_cast<void *>(&authDataLength));
    buffer.insert(buffer.begin(), writePointer, writePointer + sizeof(uint32_t));
    tag = AUTH_DATA;
    writePointer = static_cast<uint8_t*>(static_cast<void *>(&tag));
    buffer.insert(buffer.begin(), writePointer, writePointer + sizeof(AuthAttributeType));

    tag = AUTH_SIGNATURE;
    writePointer = static_cast<uint8_t*>(static_cast<void *>(&tag));
    buffer.insert(buffer.end(), writePointer, writePointer + sizeof(AuthAttributeType));

    PackToBuffer(authAttributesPosition_.find(AUTH_SIGNATURE), dataLength, writePointer, buffer);

    authDataLength = buffer.size();
    writePointer = static_cast<uint8_t*>(static_cast<void *>(&authDataLength));
    buffer.insert(buffer.begin(), writePointer, writePointer + sizeof(uint32_t));
    tag = AUTH_ROOT;
    writePointer = static_cast<uint8_t*>(static_cast<void *>(&tag));
    buffer.insert(buffer.begin(), writePointer, writePointer + sizeof(AuthAttributeType));
    return SUCCESS;
}


void AuthAttributes::Write32Array(std::vector<uint32_t> &uint32ArraylValue, uint8_t *writePointer,
                                  std::vector<uint8_t> &buffer)
{
    for (std::size_t num = 0; num < uint32ArraylValue.size(); num++) {
        writePointer = static_cast<uint8_t*>(static_cast<void *>(&uint32ArraylValue[num]));
        buffer.insert(buffer.end(), writePointer, writePointer + sizeof(uint32_t));
    }
}
void AuthAttributes::Write64Array(std::vector<uint64_t> &uint64ArraylValue, uint8_t *writePointer,
                                  std::vector<uint8_t> &buffer)
{
    for (std::size_t num = 0; num < uint64ArraylValue.size(); num++) {
        writePointer = static_cast<uint8_t*>(static_cast<void *>(&uint64ArraylValue[num]));
        buffer.insert(buffer.end(), writePointer, writePointer + sizeof(uint64_t));
    }
}

void  AuthAttributes::PackToBuffer(std::map<AuthAttributeType, ValueType>::iterator iter,
                                   uint32_t dataLength, uint8_t *writePointer,
                                   std::vector<uint8_t> &buffer)
{
    bool boolValue;
    uint32_t uint32Value;
    uint64_t uint64Value;
    std::vector<uint32_t> uint32ArraylValue;
    std::vector<uint64_t> uint64ArraylValue;
    std::vector<uint8_t> uint8ArrayValue;
    switch (iter->second) {
        case BOOLTYPE:
            GetBoolValue(iter->first, boolValue);
            WriteDataLength(buffer, writePointer, sizeof(bool));
            writePointer = static_cast<uint8_t*>(static_cast<void *>(&boolValue));
            buffer.insert(buffer.end(), writePointer, writePointer + sizeof(bool));
            break;
        case UINT32TYPE:
            GetUint32Value(iter->first, uint32Value);
            WriteDataLength(buffer, writePointer, sizeof(uint32_t));
            writePointer = static_cast<uint8_t*>(static_cast<void *>(&uint32Value));
            buffer.insert(buffer.end(), writePointer, writePointer + sizeof(uint32_t));
            break;
        case UINT64TYPE:
            GetUint64Value(iter->first, uint64Value);
            WriteDataLength(buffer, writePointer, sizeof(uint64_t));
            writePointer = static_cast<uint8_t*>(static_cast<void *>(&uint64Value));
            buffer.insert(buffer.end(), writePointer, writePointer + sizeof(uint64_t));
            break;
        case UINT32ARRAYTYPE:
            GetUint32ArrayValue(iter->first, uint32ArraylValue);
            WriteDataLength(buffer, writePointer, sizeof(uint32_t) * uint32ArraylValue.size());
            Write32Array(uint32ArraylValue, writePointer, buffer);
            break;
        case UINT64ARRAYTYPE:
            GetUint64ArrayValue(iter->first, uint64ArraylValue);
            WriteDataLength(buffer, writePointer, sizeof(uint64_t) * uint64ArraylValue.size());
            Write64Array(uint64ArraylValue, writePointer, buffer);
            break;
        case UINT8ARRAYTYPE:
            if (GetUint8ArrayValue(iter->first, uint8ArrayValue)) {
                WriteDataLength(buffer, writePointer, 0);
                break;
            }
            dataLength = sizeof(uint8_t) * uint8ArrayValue.size();
            WriteDataLength(buffer, writePointer, dataLength);
            buffer.insert(buffer.end(), uint8ArrayValue.begin(), uint8ArrayValue.begin() + dataLength);
            break;
        default:
            break;
    }
}

void AuthAttributes::WriteDataLength(std::vector<uint8_t> &buffer, uint8_t *writePointer, uint32_t dataLength)
{
        writePointer = static_cast<uint8_t*>(static_cast<void *>(&dataLength));
        buffer.insert(buffer.end(), writePointer, writePointer + sizeof(uint32_t));
}
}
}
}
