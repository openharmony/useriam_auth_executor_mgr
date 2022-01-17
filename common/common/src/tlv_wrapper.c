/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#include "tlv_wrapper.h"

#include <string.h>

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"

static int PutTlvObject(TlvListNode *head, int type, unsigned int length, const void *value)
{
    if ((head == NULL) || (value == NULL) || (length > MAX_BUFFER_SIZE)) {
        return PARAM_ERR;
    }

    TlvType *tlv = (TlvType *)Malloc(sizeof(TlvType));
    if (tlv == NULL) {
        return MALLOC_FAIL;
    }

    tlv->type = type;
    tlv->length = length;
    tlv->value = NULL;
    if (length > 0) {
        tlv->value = (unsigned char *)Malloc(length);
        if (tlv->value == NULL) {
            Free(tlv);
            tlv = NULL;
            return MALLOC_FAIL;
        }

        if (memcpy_s(tlv->value, length, value, length) != EOK) {
            Free(tlv->value);
            tlv->value = NULL;
            Free(tlv);
            tlv = NULL;
            return MEMCPY_ERR;
        }
    }

    TlvObject object;
    object.value = tlv;
    int ret = AddTlvNode(head, &object);
    if (ret != OPERA_SUCC) {
        if (object.value != NULL) {
            Free(tlv->value);
            tlv->value = NULL;
            Free(object.value);
            object.value = NULL;
        }
    }
    return ret;
}

int SerializeTlvWrapper(const TlvListNode *head, unsigned char *buffer, unsigned int maxSize, unsigned int *contentSize)
{
    if (head == NULL || buffer == NULL || contentSize == NULL || maxSize == 0) {
        return PARAM_ERR;
    }

    unsigned int offset = 0;
    TlvListNode *node = head->next;
    while (node != NULL) {
        TlvType *tlv = node->data.value;
        int type = Ntohl(tlv->type);
        if ((offset > UINT32_MAX - sizeof(int)) || (offset + sizeof(int) > maxSize) ||
            (memcpy_s(buffer + offset, sizeof(int), &type, sizeof(int)) != EOK)) {
            return MEMCPY_ERR;
        }
        offset += sizeof(int);
        unsigned int len = Ntohl(tlv->length);
        if ((offset > UINT32_MAX - sizeof(int)) || (offset + sizeof(int) > maxSize) ||
            (memcpy_s(buffer + offset, sizeof(int), &len, sizeof(int)) != EOK)) {
            return MEMCPY_ERR;
        }
        offset += sizeof(int);
        if ((offset > UINT32_MAX - tlv->length) || (offset + tlv->length > maxSize) ||
            ((tlv->length != 0) && (memcpy_s(buffer + offset, maxSize - offset, tlv->value, tlv->length) != EOK))) {
            return MEMCPY_ERR;
        }
        offset += tlv->length;
        node = node->next;
    }

    *contentSize = offset;
    return OPERA_SUCC;
}

int ParseGetHeadTag(const TlvListNode *node, int *tag)
{
    if (node == NULL || tag == NULL) {
        return PARAM_ERR;
    }
    TlvType *tlv = node->data.value;
    if (tlv == NULL) {
        return TAG_NOT_EXIST;
    }
    *tag = tlv->type;
    return OPERA_SUCC;
}

int ParseTlvWrapper(const unsigned char *buffer, unsigned int bufferSize, TlvListNode *head)
{
    if (buffer == NULL || bufferSize == 0 || bufferSize > MAX_BUFFER_SIZE || head == NULL) {
        return PARAM_ERR;
    }

    unsigned int offset = 0;
    while (offset < bufferSize) {
        if ((bufferSize - offset) < (sizeof(int) + sizeof(int))) {
            LOG_ERROR("bufferSize = %{public}u, offset = %{public}u", bufferSize, offset);
            return OPERA_FAIL;
        }
        int type = Ntohl(*(int *)(buffer + offset));
        offset += sizeof(int);
        unsigned int length = Ntohl(*(int *)(buffer + offset));
        offset += sizeof(int);
        if (length > (bufferSize - offset)) {
            LOG_ERROR("bufferSize = %{public}u, offset = %{public}u, length = %{public}u", bufferSize, offset, length);
            return OPERA_FAIL;
        }
        int ret = PutTlvObject(head, type, length, buffer + offset);
        if (ret != 0) {
            return ret;
        }
        offset += length;
    }

    return OPERA_SUCC;
}

int TlvAppendByte(TlvListNode *head, int type, const unsigned char *value, unsigned int length)
{
    if (head == NULL || value == NULL) {
        return PARAM_ERR;
    }
    return PutTlvObject(head, type, length, value);
}

int TlvAppendShort(TlvListNode *head, int type, short value)
{
    if (head == NULL) {
        return PARAM_ERR;
    }
    short tempValue = Ntohs(value);
    return PutTlvObject(head, type, sizeof(short), &tempValue);
}

int TlvAppendInt(TlvListNode *head, int type, uint32_t value)
{
    if (head == NULL) {
        return PARAM_ERR;
    }
    uint32_t tempValue = Ntohl(value);
    return PutTlvObject(head, type, sizeof(int32_t), &tempValue);
}

int TlvAppendLong(TlvListNode *head, int type, uint64_t value)
{
    if (head == NULL) {
        return PARAM_ERR;
    }
    uint64_t tempValue = Ntohll(value);
    return PutTlvObject(head, type, sizeof(int64_t), &tempValue);
}

int TlvAppendObject(TlvListNode *head, int type, const unsigned char *buffer, unsigned int length)
{
    if (head == NULL || buffer == NULL || length == 0 || length > MAX_BUFFER_SIZE) {
        return PARAM_ERR;
    }
    return PutTlvObject(head, type, length, buffer);
}

static uint8_t *GetTlvValue(TlvListNode *head, int msgType, uint32_t *len)
{
    if ((head == NULL) || (len == NULL)) {
        LOG_ERROR("GetTlvValue input invalid");
        return NULL;
    }
    TlvObject node = head->data;
    TlvType *tlv = node.value;
    if (tlv == NULL) {
        LOG_ERROR("GetTlvValue tlv is NULL");
        return NULL;
    }
    int32_t type = tlv->type;
    *len = tlv->length;
    if ((type != msgType) || (*len == 0)) {
        LOG_ERROR("GetTlvValue return type = %d, len  = %u, msgType = %d", type, *len, msgType);
        return NULL;
    }

    return tlv->value;
}

int32_t ParseUint64Para(TlvListNode *node, int msgType, uint64_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint64Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint64_t))) {
        LOG_ERROR("ParseUint64Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = Ntohll(*(uint64_t *)val);
    return OPERA_SUCC;
}

int32_t ParseInt64Para(TlvListNode *node, int msgType, int64_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseInt64Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(int64_t))) {
        LOG_ERROR("ParseInt64Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = (int64_t)Ntohll(*(uint64_t *)val);
    return OPERA_SUCC;
}

int32_t ParseUint32Para(TlvListNode *node, int msgType, uint32_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint32Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint32_t))) {
        LOG_ERROR("ParseUint32Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = Ntohl(*(uint32_t *)val);
    return OPERA_SUCC;
}

int32_t ParseInt32Para(TlvListNode *node, int msgType, int32_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseInt32Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(int32_t))) {
        LOG_ERROR("ParseInt32Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = (int32_t)Ntohl(*(uint32_t *)val);
    return OPERA_SUCC;
}

int32_t ParseShortPara(TlvListNode *node, int msgType, short *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseInt32Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(short))) {
        LOG_ERROR("ParseInt32Para GetTlvValue failed");
        return OPERA_FAIL;
    }
    *retVal = Ntohs(*(short *)val);
    return OPERA_SUCC;
}

Buffer *ParseBuffPara(TlvListNode *node, int msgType)
{
    if (node == NULL) {
        LOG_ERROR("ParseBuffPara parameter check failed");
        return NULL;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if (val == NULL) {
        LOG_ERROR("ParseBuffPara GetTlvValue failed");
        return NULL;
    }
    Buffer *buff = CreateBufferByData(val, len);
    if (buff == NULL) {
        LOG_ERROR("ParseBuffPara CreateBufferByData failed");
        return NULL;
    }
    return buff;
}

int32_t ParseUint8Para(TlvListNode *node, int msgType, uint8_t *retVal)
{
    if ((node == NULL) || (retVal == NULL)) {
        LOG_ERROR("ParseUint8Para parameter check failed");
        return PARAM_ERR;
    }
    uint32_t len = 0;
    uint8_t *val = GetTlvValue(node, msgType, &len);
    if ((val == NULL) || (len != sizeof(uint8_t))) {
        LOG_ERROR("ParseUint8Para GetTlvValue failed");
        return PARAM_ERR;
    }
    *retVal = *val;
    return OPERA_SUCC;
}


int32_t GetUint64Para(TlvListNode *head, int msgType, uint64_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetUint64Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseUint64Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

int32_t GetInt64Para(TlvListNode *head, int msgType, int64_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetInt64Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseInt64Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

int32_t GetUint32Para(TlvListNode *head, int msgType, uint32_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetUint32Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseUint32Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

int32_t GetInt32Para(TlvListNode *head, int msgType, int32_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetInt32Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseInt32Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}

Buffer *GetBuffPara(TlvListNode *head, int msgType)
{
    if (head == NULL) {
        LOG_ERROR("GetBuffPara parameter check failed");
        return NULL;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return NULL;
        }
        if (nodeType == msgType) {
            return ParseBuffPara(node, msgType);
        }
        node = node->next;
    }
    return NULL;
}

int32_t GetUint8Para(TlvListNode *head, int msgType, uint8_t *retVal)
{
    if ((head == NULL) || (retVal == NULL)) {
        LOG_ERROR("GetUint8Para parameter check failed");
        return PARAM_ERR;
    }
    TlvListNode *node = head;
    while (node != NULL) {
        int nodeType;
        int32_t ret = ParseGetHeadTag(node, &nodeType);
        if (ret != OPERA_SUCC) {
            return ret;
        }
        if (nodeType == msgType) {
            return ParseUint8Para(node, msgType, retVal);
        }
        node = node->next;
    }
    return PARAM_ERR;
}