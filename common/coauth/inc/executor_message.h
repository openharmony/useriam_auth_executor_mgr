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

#ifndef USERIAM_EXECUTOR_MESSAGE_H
#define USERIAM_EXECUTOR_MESSAGE_H

#include <stdint.h>

#include "buffer.h"
#include "defines.h"

typedef enum AuthAttributeType {
    AUTH_INVALID = 0,
    AUTH_ROOT = 1000000,
    AUTH_RESULT_CODE = 1000001,
    AUTH_SIGNATURE = 1000002,
    AUTH_IDENTIFY_MODE = 1000003,
    AUTH_TEMPLATE_ID = 1000004,
    AUTH_TEMPLATE_ID_LIST = 1000005,
    AUTH_REMAIN_COUNT = 1000006,
    AUTH_REMAIN_TIME = 1000007,
    AUTH_SCHEDULE_ID = 1000008,
    AUTH_CALLER_NAME = 1000009,
    AUTH_SCHEDULE_VERSION = 1000010,
    AUTH_LOCK_OUT_TEMPLATE = 1000011,
    AUTH_UNLOCK_TEMPLATE = 1000012,
    AUTH_DATA = 1000013,
    AUTH_SUBTYPE = 1000014,
    AUTH_CAPABILITY_LEVEL = 1000015,
} AuthAttributeType;

typedef struct ExecutorResultInfo {
    Buffer *data;
    Buffer *sign;
    int32_t result;
    uint64_t scheduleId;
    uint64_t templateId;
    uint64_t authSubType;
    uint32_t capabilityLevel;
} ExecutorResultInfo;

ExecutorResultInfo *GetExecutorResultInfo(const Buffer *executorResultInfo);
void DestoryExecutorResultInfo(ExecutorResultInfo *result);

#endif // USERIAM_EXECUTOR_MESSAGE_H