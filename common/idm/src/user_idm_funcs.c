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

#include "user_idm_funcs.h"

#include "securec.h"

#include "adaptor_log.h"
#include "adaptor_memory.h"
#include "coauth.h"
#include "coauth_sign_centre.h"
#include "idm_database.h"
#include "user_sign_centre.h"

static int32_t PinPermissionCheck(int32_t userId, UserAuthTokenHal *authToken)
{
    CredentialInfoHal credentialInfo;
    int32_t ret = QueryCredentialInfo(userId, PIN_AUTH, &credentialInfo);
    if (ret == RESULT_NOT_FOUND) {
        return RESULT_SUCCESS;
    } else if (ret == RESULT_SUCCESS) {
        LOG_INFO("pin already exists, legal token is required");
        uint64_t challenge;
        ret = GetChallenge(&challenge);
        if (ret != RESULT_SUCCESS || challenge != authToken->challenge) {
            LOG_ERROR("check challenge failed, token is invalid");
            return RESULT_BAD_MATCH;
        }
        if (!IsValidTokenTime(authToken->time)) {
            LOG_ERROR("check token time failed, token is invalid");
            return RESULT_VERIFY_TOKEN_FAIL;
        }
        return UserAuthTokenVerify(authToken);
    } else {
        LOG_ERROR("PinPermissionCheck failed");
        return ret;
    }
}

static int32_t FacePermissionCheck(int32_t userId, UserAuthTokenHal *authToken)
{
    CredentialInfoHal credentialInfo;
    int32_t ret = QueryCredentialInfo(userId, FACE_AUTH, &credentialInfo);
    if (ret != RESULT_NOT_FOUND) {
        LOG_ERROR("The face has been recorded");
        return RESULT_EXCEED_LIMIT;
    }
    uint64_t challenge;
    ret = GetChallenge(&challenge);
    if (ret != RESULT_SUCCESS || challenge != authToken->challenge) {
        LOG_ERROR("check challenge failed, token is invalid");
        return RESULT_BAD_MATCH;
    }
    if (!IsValidTokenTime(authToken->time)) {
        LOG_ERROR("check token time failed, token is invalid");
        return RESULT_VERIFY_TOKEN_FAIL;
    }
    return UserAuthTokenVerify(authToken);
}

int32_t CheckEnrollPermission(PermissionCheckParam param, uint64_t *scheduleId)
{
    if (scheduleId == NULL) {
        LOG_ERROR("scheduleId is null");
        return RESULT_BAD_PARAM;
    }

    UserAuthTokenHal *authToken = (UserAuthTokenHal *)param.token;
    int32_t ret;
    if (param.authType == PIN_AUTH) {
        ret = PinPermissionCheck(param.userId, authToken);
    } else if (param.authType == FACE_AUTH) {
        ret = FacePermissionCheck(param.userId, authToken);
    } else {
        LOG_ERROR("AuthType is invalid");
        ret = RESULT_BAD_MATCH;
    }
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("permission check failed");
        return ret;
    }
    uint64_t challenge;
    ret = GetChallenge(&challenge);
    CoAuthSchedule *enrollSchedule = GenerateIdmSchedule(challenge, param.authType, param.authSubType);
    if (enrollSchedule == NULL) {
        LOG_ERROR("enrollSchedule malloc failed");
        return RESULT_NO_MEMORY;
    }
    ret = AddCoAuthSchedule(enrollSchedule);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("add coauth schedule failed");
        goto EXIT;
    }

    ret = AssociateCoauthSchedule(enrollSchedule->scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("idm associate coauth schedule failed");
        goto EXIT;
    }
    *scheduleId = enrollSchedule->scheduleId;

EXIT:
    DestroyCoAuthSchedule(enrollSchedule);
    return ret;
}

static void GetInfoFromToken(CredentialInfoHal *credentialInfo, ScheduleTokenHal token)
{
    credentialInfo->authType = token.authType;
    credentialInfo->authSubType = token.authSubType;
    credentialInfo->templateId = token.templateId;
    credentialInfo->capabilityLevel = token.capabilityLevel;
}

int32_t AddCredentialFunc(const uint8_t *enrollToken, uint32_t tokenLen, uint64_t *credentialId)
{
    if (enrollToken == NULL || credentialId == NULL || tokenLen != sizeof(ScheduleTokenHal)) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    ScheduleTokenHal token;
    if (memcpy_s(&token, sizeof(ScheduleTokenHal), enrollToken, tokenLen) != EOK) {
        LOG_ERROR("token copy failed");
        return RESULT_BAD_COPY;
    }
    uint64_t currentSchedule;
    int32_t ret = GetScheduleId(&currentSchedule);
    if (ret != RESULT_SUCCESS || token.scheduleId != currentSchedule || IsSessionTimeout()) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_REACH_LIMIT;
    }

    ret = CoAuthTokenVerify(&token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to verify the token");
        return RESULT_BAD_SIGN;
    }
    int32_t userId;
    ret = GetUserId(&userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get userId failed");
        return ret;
    }
    CredentialInfoHal credentialInfo;
    GetInfoFromToken(&credentialInfo, token);
    ret = AddCredentialInfo(userId, &credentialInfo);
    if (ret == RESULT_SUCCESS) {
        *credentialId = credentialInfo.credentialId;
    }
    return ret;
}

int32_t DeleteCredentialFunc(CredentialDeleteParam param, CredentialInfoHal *credentialInfo)
{
    if (credentialInfo == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    UserAuthTokenHal token;
    if (memcpy_s(&token, sizeof(UserAuthTokenHal), param.token, AUTH_TOKEN_LEN) != EOK) {
        LOG_ERROR("token copy failed");
        return RESULT_BAD_COPY;
    }

    uint64_t challenge;
    int32_t ret = GetChallenge(&challenge);
    if (ret != RESULT_SUCCESS || challenge != token.challenge || IsSessionTimeout()) {
        LOG_ERROR("check challenge failed");
        return RESULT_BAD_SIGN;
    }

    ret = UserAuthTokenVerify(&token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to verify the token");
        return RESULT_BAD_SIGN;
    }
    ret = DeleteCredentialInfo(param.userId, param.credentialId, credentialInfo);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete database info failed");
        return RESULT_BAD_SIGN;
    }
    return ret;
}

int32_t QueryCredentialFunc(int32_t userId, uint32_t authType,
    CredentialInfoHal **credentialInfoArray, uint32_t *credentialNum)
{
    if (credentialInfoArray == NULL || credentialNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    if (authType == DEFAULT_AUTH_TYPE) {
        return QueryCredentialInfoAll(userId, credentialInfoArray, credentialNum);
    }
    CredentialInfoHal credentialInfo;
    int32_t ret = QueryCredentialInfo(userId, authType, &credentialInfo);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }

    *credentialInfoArray = Malloc(sizeof(CredentialInfoHal));
    if (*credentialInfoArray == NULL) {
        LOG_ERROR("credentialInfoArray malloc failed");
        return RESULT_NO_MEMORY;
    }
    if (memcpy_s(*credentialInfoArray, sizeof(CredentialInfoHal), &credentialInfo, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("credentialInfoArray copy failed");
        Free(*credentialInfoArray);
        *credentialInfoArray = NULL;
        return RESULT_BAD_COPY;
    }
    *credentialNum = 1;
    return RESULT_SUCCESS;
}

int32_t GetUserSecureUidFunc(int32_t userId, uint64_t *secureUid, EnrolledInfoHal **enrolledInfoArray,
    uint32_t *enrolledNum)
{
    if (secureUid == NULL || enrolledInfoArray == NULL || enrolledNum == NULL) {
        LOG_ERROR("param is null");
        return RESULT_BAD_PARAM;
    }
    int32_t ret = GetSecureUid(userId, secureUid);
    if (ret != RESULT_SUCCESS) {
        return ret;
    }
    return GetEnrolledInfo(userId, enrolledInfoArray, enrolledNum);
}

int32_t CancelScheduleIdFunc(uint64_t *scheduleId)
{
    if (scheduleId == NULL) {
        LOG_ERROR("scheduleId is null");
        return RESULT_BAD_PARAM;
    }

    int32_t ret = GetScheduleId(scheduleId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get scheduleId failed");
        return ret;
    }
    BreakOffCoauthSchedule();

    return ret;
}

int32_t UpdateCredentialFunc(const uint8_t *enrollToken, uint32_t tokenLen, uint64_t *credentialId,
    CredentialInfoHal *deletedCredential)
{
    if (enrollToken == NULL || credentialId == NULL || tokenLen != sizeof(ScheduleTokenHal) ||
        deletedCredential == NULL) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    ScheduleTokenHal token;
    if (memcpy_s(&token, sizeof(ScheduleTokenHal), enrollToken, tokenLen) != EOK) {
        LOG_ERROR("token copy failed");
        return RESULT_BAD_COPY;
    }
    if (token.authType != PIN_AUTH) {
        LOG_ERROR("authType isn't pin");
        return RESULT_BAD_PARAM;
    }
    uint64_t currentSchedule;
    int32_t ret = GetScheduleId(&currentSchedule);
    if (ret != RESULT_SUCCESS || token.scheduleId != currentSchedule || IsSessionTimeout()) {
        LOG_ERROR("schedule is mismatch");
        return RESULT_REACH_LIMIT;
    }
    ret = CoAuthTokenVerify(&token);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("failed to verify the token");
        return RESULT_BAD_SIGN;
    }

    int32_t userId;
    ret = GetUserId(&userId);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get userId failed");
        return ret;
    }
    ret = QueryCredentialInfo(userId, PIN_AUTH, deletedCredential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query failed");
        return ret;
    }
    ret = DeleteCredentialInfo(userId, deletedCredential->credentialId, deletedCredential);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete failed");
        return ret;
    }

    CredentialInfoHal credentialInfo;
    credentialInfo.authType = token.authType;
    credentialInfo.authSubType = token.authSubType;
    credentialInfo.templateId = token.templateId;
    credentialInfo.capabilityLevel = token.capabilityLevel;
    ret = AddCredentialInfo(userId, &credentialInfo);
    if (ret == RESULT_SUCCESS) {
        *credentialId = credentialInfo.credentialId;
    }
    return ret;
}