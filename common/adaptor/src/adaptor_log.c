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

#include "adaptor_log.h"

#include "hilog/log_c.h"

#ifndef LOG_DOMAIN
#define LOG_DOMAIN 0xD002422
#endif
#ifndef APP_LOG_TAG
#define APP_LOG_TAG "IamBase"
#endif

void LogInfo(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    HiLogPrint(LOG_CORE, LOG_INFO, LOG_DOMAIN, APP_LOG_TAG, format, ap);
    va_end(ap);
}

void LogError(const char *format, ...)
{
    va_list ap;
    va_start(ap, format);
    HiLogPrint(LOG_CORE, LOG_ERROR, LOG_DOMAIN, APP_LOG_TAG, format, ap);
    va_end(ap);
}