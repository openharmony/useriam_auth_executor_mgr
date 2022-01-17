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

#ifndef USER_AUTH_FUNCS_H
#define USER_AUTH_FUNCS_H

#include "buffer.h"

#include "user_sign_centre.h"
#include "context_manager.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint64_t scheduleId;
    uint8_t ExecutorSign[SHA256_SIGN_LEN];
} ExecutorResult;

int32_t GenerateSolutionFunc(AuthSolutionHal param, uint64_t **scheduleIdArray, uint32_t *scheduleNum);
int32_t RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleToken, UserAuthTokenHal *authToken,
    uint64_t **scheduleIdArray, uint32_t *scheduleNum);
int32_t CancelContextFunc(uint64_t contextId, uint64_t **scheduleIdArray, uint32_t *scheduleNum);

#ifdef __cplusplus
}
#endif

#endif // USER_AUTH_FUNCS_H
