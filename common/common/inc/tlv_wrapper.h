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

#ifndef TLV_WRAPPER_H
#define TLV_WRAPPER_H

#include <stdint.h>

#include "tlv_base.h"
#include "buffer.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_BUFFER_SIZE 512000
#define TLV_HEADER_LEN (sizeof(int) + sizeof(unsigned int))

int SerializeTlvWrapper(const TlvListNode *head, unsigned char *buffer,
    unsigned int maxSize, unsigned int *contentSize);

int ParseTlvWrapper(const unsigned char *buffer, unsigned int bufferSize, TlvListNode *head);
int ParseGetHeadTag(const TlvListNode *node, int *tag);

int32_t ParseUint64Para(TlvListNode *node, int msgType, uint64_t *retVal);
int32_t ParseInt64Para(TlvListNode *node, int msgType, int64_t *retVal);
int32_t ParseUint32Para(TlvListNode *node, int msgType, uint32_t *retVal);
int32_t ParseInt32Para(TlvListNode *node, int msgType, int32_t *retVal);
Buffer *ParseBuffPara(TlvListNode *node, int msgType);
int32_t ParseUint8Para(TlvListNode *node, int msgType, uint8_t *retVal);

int32_t GetUint64Para(TlvListNode *head, int msgType, uint64_t *retVal);
int32_t GetInt64Para(TlvListNode *head, int msgType, int64_t *retVal);
int32_t GetUint32Para(TlvListNode *head, int msgType, uint32_t *retVal);
int32_t GetInt32Para(TlvListNode *head, int msgType, int32_t *retVal);
Buffer *GetBuffPara(TlvListNode *head, int msgType);
int32_t GetUint8Para(TlvListNode *head, int msgType, uint8_t *retVal);

int TlvAppendByte(TlvListNode *head, int type, const unsigned char *value, unsigned int length);
int TlvAppendShort(TlvListNode *head, int type, short value);
int TlvAppendInt(TlvListNode *head, int type, uint32_t value);
int TlvAppendLong(TlvListNode *head, int type, uint64_t value);
int TlvAppendObject(TlvListNode *head, int type, const unsigned char *buffer, unsigned int length);

#ifdef __cplusplus
}
#endif

#endif // TLV_WRAPPER_H