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

#include "userauth_interface.h"

#include "securec.h"

#include "idm_session.h"
#include "user_idm_funcs.h"
#include "adaptor_log.h"
#include "coauth_interface.h"
#include "coauth_sign_centre.h"
#include "idm_database.h"

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace Hal {

typedef struct {
    uint64_t credentialId;
    uint32_t authType;
    uint64_t authSubType;
    uint64_t templateId;
} CredentialInfo;

typedef struct {
    uint32_t authType;
    uint64_t enrolledId;
} EnrolledInfo;

int32_t OpenSession(int32_t userId, uint64_t &challenge)
{
    return OpenEditSession(userId, &challenge);
}

int32_t CloseSession()
{
    return CloseEditSession();
}

int32_t GetScheduleId(std::vector<uint8_t> authToken, int32_t userId, uint32_t authType, uint64_t authSubType,
    uint64_t &scheduleId)
{
    LOG_INFO("begin");
    if (authToken.size() != sizeof(UserAuth::UserAuthToken) && authType != PIN_AUTH) {
        LOG_ERROR("authToken len is invalid");
        return RESULT_BAD_PARAM;
    }
    LOG_ERROR("1111");
    PermissionCheckParam param;
    if (authToken.size() == sizeof(UserAuth::UserAuthToken) && 
        memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        LOG_ERROR("1111");
        return RESULT_BAD_COPY;
    }
    LOG_ERROR("1111");
    param.authType = authType;
    param.userId = userId;
    param.authSubType = authSubType;
    return CheckEnrollPermission(param, &scheduleId);
}

int32_t CancelScheduleId(uint64_t &scheduleId)
{
    LOG_INFO("begin");
    return CancelScheduleIdFunc(&scheduleId);
}

int32_t AddCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId)
{
    LOG_INFO("begin");
    if (enrollToken.size() != sizeof(CoAuth::ScheduleToken)) {
        LOG_ERROR("enrollToken is invalid %{public}u", enrollToken.size());
        return RESULT_BAD_PARAM;
    }
    uint8_t enrollTokenIn[sizeof(ScheduleTokenHal)];
    if (memcpy_s(enrollTokenIn, sizeof(ScheduleTokenHal), &enrollToken[0], enrollToken.size()) != EOK) {
        LOG_ERROR("enrollToken copy failed");
        return RESULT_BAD_COPY;
    }
    return AddCredentialFunc(enrollTokenIn, (uint32_t)sizeof(ScheduleTokenHal), &credentialId);
}

int32_t DeleteCredential(int32_t userId, uint64_t credentialId, std::vector<uint8_t> authToken,
    CredentialInfo &credentialInfo)
{
    LOG_INFO("begin");
    authToken.resize(sizeof(UserAuth::UserAuthToken));
    if (authToken.size() != sizeof(UserAuth::UserAuthToken)) {
        LOG_ERROR("authToken len is invalid");
        return RESULT_BAD_PARAM;
    }
    CredentialDeleteParam param;
    if (memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        LOG_ERROR("param token copy failed");
        return RESULT_BAD_COPY;
    }
    param.userId = userId;
    param.credentialId = credentialId;
    CredentialInfoHal credentialInfoHal;
    int32_t ret = DeleteCredentialFunc(param, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete failed");
        return ret;
    }
    if (memcpy_s(&credentialInfo, sizeof(CredentialInfo), &credentialInfoHal, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_BAD_COPY;
    }
    return RESULT_SUCCESS;
}

int32_t QueryCredential(int32_t userId, uint32_t authType, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("begin");
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = QueryCredentialFunc(userId, authType, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        return ret;
    }
    for (int i = 0; i < num; i++) {
        CredentialInfo credentialInfo;
        if (memcpy_s(&credentialInfo, sizeof(CredentialInfo), 
            &credentialInfoHals[i], sizeof(CredentialInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(credentialInfoHals);
            credentialInfos.clear();
            return RESULT_BAD_COPY;
        }
        credentialInfos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    return RESULT_SUCCESS;
}

int32_t GetSecureUid(int32_t userId, uint64_t &secureUid, std::vector<EnrolledInfo> &enrolledInfos)
{
    LOG_INFO("begin");
    EnrolledInfoHal *enrolledInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = GetUserSecureUidFunc(userId, &secureUid, &enrolledInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get user secureUid failed");
        return ret;
    }
    for (int i = 0; i < num; i++) {
        EnrolledInfo enrolledInfo;
        if (memcpy_s(&enrolledInfo, sizeof(EnrolledInfo), &enrolledInfoHals[i], sizeof(EnrolledInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(enrolledInfoHals);
            enrolledInfos.clear();
            return RESULT_BAD_COPY;
        }
        enrolledInfos.push_back(enrolledInfo);
    }
    free(enrolledInfoHals);
    return RESULT_SUCCESS;
}

int32_t DeleteUserEnforce(int32_t userId, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("begin");
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = DeleteUserInfo(userId, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        return ret;
    }
    for (int i = 0; i < num; i++) {
        CredentialInfo credentialInfo;
        if (memcpy_s(&credentialInfo, sizeof(CredentialInfo), 
            &credentialInfoHals[i], sizeof(CredentialInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(credentialInfoHals);
            credentialInfos.clear();
            return RESULT_BAD_COPY;
        }
        credentialInfos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    return RESULT_SUCCESS;
}

int32_t DeleteUser(int32_t userId, std::vector<uint8_t> authToken, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("begin");
    authToken.resize(sizeof(UserAuthTokenHal));
    if (authToken.size() != sizeof(UserAuthTokenHal)) {
        LOG_ERROR("authToken is invalid");
        return RESULT_BAD_PARAM;
    }
    // UserAuthTokenHal authTokenStruct;
    // if (memcpy_s(&authTokenStruct, sizeof(UserAuthTokenHal), &authToken[0], authToken.size()) != EOK) {
    //     LOG_ERROR("authTokenStruct copy failed");
    //     return RESULT_BAD_COPY;
    // }
    // uint64_t challenge;
    // int32_t ret = GetChallenge(&challenge);
    // if (ret != RESULT_SUCCESS) {
    //     LOG_ERROR("get challenge failed");
    //     return ret;
    // }
    // if (challenge != authTokenStruct.challenge || UserAuthTokenVerify(&authTokenStruct) != RESULT_SUCCESS) {
    //     LOG_ERROR("verify token failed");
    //     return RESULT_BAD_SIGN;
    // }
    return DeleteUserEnforce(userId, credentialInfos);
}

int32_t UpdateCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId, CredentialInfo &deletedCredential)
{
    LOG_INFO("begin");
    if (enrollToken.size() != sizeof(CoAuth::ScheduleToken)) {
        LOG_ERROR("enrollToken is invalid");
        return RESULT_BAD_PARAM;
    }
    uint8_t enrollTokenIn[sizeof(ScheduleTokenHal)];
    if (memcpy_s(enrollTokenIn, sizeof(ScheduleTokenHal), &enrollToken[0], enrollToken.size()) != EOK) {
        LOG_ERROR("enrollToken copy failed");
        return RESULT_BAD_COPY;
    }
    CredentialInfoHal credentialInfoHal;
    int32_t ret = 
        UpdateCredentialFunc(enrollTokenIn, (uint32_t)sizeof(ScheduleTokenHal), &credentialId, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("update failed");
        return ret;
    }
    if (memcpy_s(&deletedCredential, sizeof(CredentialInfo), &credentialInfoHal, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_BAD_COPY;
    }
    return RESULT_SUCCESS;
}

}
}
}
}