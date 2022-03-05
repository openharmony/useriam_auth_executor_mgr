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

#include "user_auth_funcs.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_time.h"
#include "coauth_sign_centre.h"
#include "context_manager.h"
#include "idm_database.h"
#include "user_sign_centre.h"

int32_t GenerateSolutionFunc(AuthSolutionHal param, uint64_t **scheduleIdArray, uint32_t *scheduleNum)
{
    if (scheduleIdArray == NULL || scheduleNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    UserAuthContext *authContext = GenerateContext(param);
    if (authContext == NULL) {
        LOG_ERROR("authContext is null");
        return RESULT_GENERAL_ERROR;
    }
    int32_t ret = GetScheduleIds(authContext, scheduleIdArray, scheduleNum);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(authContext);
        return ret;
    }
    return ret;
}

static int32_t GetTokenDataAndSign(UserAuthContext *context, UserAuthTokenHal *authToken)
{
    if (context == NULL || authToken == NULL) {
        LOG_ERROR("context or authToken is null");
        return RESULT_BAD_PARAM;
    }
    authToken->authResult = RESULT_SUCCESS;
    authToken->userId = context->userId;
    authToken->authTrustLevel = context->authTrustLevel;
    authToken->authType = context->authType;
    EnrolledInfoHal enrolledInfo;
    int32_t ret = GetEnrolledInfoAuthType(context->userId, authToken->authType, &enrolledInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get enrolledId info failed");
        return ret;
    }
    authToken->enrolledId = enrolledInfo.enrolledId;
    authToken->challenge = context->challenge;
    authToken->time = GetSystemTime();
    return UserAuthTokenSign(authToken);
}

int32_t RequestAuthResultFunc(uint64_t contextId, const Buffer *scheduleToken, UserAuthTokenHal *authToken,
    uint64_t **scheduleIdArray, uint32_t *scheduleNum)
{
    if (scheduleToken == NULL || authToken == NULL || scheduleIdArray == NULL || scheduleNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    ScheduleTokenHal scheduleTokenStruct;
    if (memcpy_s(&scheduleTokenStruct, sizeof(ScheduleTokenHal), scheduleToken->buf,
        scheduleToken->contentSize) != EOK) {
        LOG_ERROR("scheduleTokenStruct copy failed");
        return RESULT_BAD_COPY;
    }
    int32_t ret = CoAuthTokenVerify(&scheduleTokenStruct);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to verify the token");
        return RESULT_BAD_SIGN;
    }

    UserAuthContext *userAuthContext = GetContext(contextId);
    if (userAuthContext == NULL) {
        LOG_ERROR("userAuthContext is null");
        return RESULT_UNKNOWN;
    }
    ret = ScheduleOnceFinish(userAuthContext, scheduleTokenStruct.scheduleId);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(userAuthContext);
        return ret;
    }
    ret = GetScheduleIds(userAuthContext, scheduleIdArray, scheduleNum);
    if (ret != RESULT_SUCCESS) {
        DestoryContext(userAuthContext);
        return ret;
    }

    if (scheduleTokenStruct.scheduleResult == RESULT_SUCCESS) {
        ret = GetTokenDataAndSign(userAuthContext, authToken);
        if (ret != RESULT_SUCCESS) {
            LOG_ERROR("sign token failed");
            Free(*scheduleIdArray);
            *scheduleIdArray = NULL;
            *scheduleNum = 0;
            (void)memset_s(authToken, sizeof(UserAuthTokenHal), 0, sizeof(UserAuthTokenHal));
        }
    } else {
        authToken->authResult = scheduleTokenStruct.scheduleResult;
    }
    DestoryContext(userAuthContext);
    return ret;
}

int32_t CancelContextFunc(uint64_t contextId, uint64_t **scheduleIdArray, uint32_t *scheduleNum)
{
    UserAuthContext *authContext = GetContext(contextId);
    if (authContext == NULL) {
        LOG_ERROR("don't have this context");
        return RESULT_NOT_FOUND;
    }
    int32_t ret = GetScheduleIds(authContext, scheduleIdArray, scheduleNum);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get schedule faield");
    }
    DestoryContext(authContext);
    return ret;
}