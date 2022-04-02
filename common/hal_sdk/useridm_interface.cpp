/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "useridm_interface.h"

#include "userauth_interface.h"
#include "securec.h"

extern "C" {
#include "idm_session.h"
#include "user_idm_funcs.h"
#include "adaptor_log.h"
#include "coauth_interface.h"
#include "coauth_sign_centre.h"
#include "idm_database.h"
#include "lock.h"
}

namespace OHOS {
namespace UserIAM {
namespace UserIDM {
namespace Hal {

int32_t OpenSession(int32_t userId, uint64_t &challenge)
{
    GlobalLock();
    int32_t ret = OpenEditSession(userId, &challenge);
    LOG_INFO("challenge is %{public}llu", (unsigned long long)challenge);
    GlobalUnLock();
    return ret;
}

int32_t CloseSession()
{
    GlobalLock();
    int32_t ret = CloseEditSession();
    GlobalUnLock();
    return ret;
}

int32_t InitSchedulation(std::vector<uint8_t> authToken, int32_t userId, uint32_t authType, uint64_t authSubType,
    uint64_t &scheduleId)
{
    LOG_INFO("start");
    GlobalLock();
    if (authToken.size() != sizeof(UserAuth::UserAuthToken) && authType != PIN_AUTH) {
        LOG_ERROR("authToken len is invalid");
        GlobalUnLock();
        return RESULT_BAD_PARAM;
    }
    PermissionCheckParam param;
    if (authToken.size() == sizeof(UserAuth::UserAuthToken) &&
        memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    param.authType = authType;
    param.userId = userId;
    param.authSubType = authSubType;
    int32_t ret = CheckEnrollPermission(param, &scheduleId);
    GlobalUnLock();
    return ret;
}

int32_t AddCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId)
{
    LOG_INFO("start");
    GlobalLock();
    if (enrollToken.size() != sizeof(CoAuth::ScheduleToken)) {
        LOG_ERROR("enrollToken is invalid, size is %{public}zu", enrollToken.size());
        GlobalUnLock();
        return RESULT_BAD_PARAM;
    }
    uint8_t enrollTokenIn[sizeof(ScheduleTokenHal)];
    if (memcpy_s(enrollTokenIn, sizeof(ScheduleTokenHal), &enrollToken[0], enrollToken.size()) != EOK) {
        LOG_ERROR("enrollToken copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    int32_t ret = AddCredentialFunc(enrollTokenIn, static_cast<uint32_t>(sizeof(ScheduleTokenHal)), &credentialId);
    GlobalUnLock();
    return ret;
}

int32_t DeleteCredential(int32_t userId, uint64_t credentialId, std::vector<uint8_t> authToken,
    CredentialInfo &credentialInfo)
{
    LOG_INFO("start");
    GlobalLock();
    authToken.resize(sizeof(UserAuth::UserAuthToken));
    if (authToken.size() != sizeof(UserAuth::UserAuthToken)) {
        LOG_ERROR("authToken len is invalid");
        GlobalUnLock();
        return RESULT_BAD_PARAM;
    }
    CredentialDeleteParam param;
    if (memcpy_s(param.token, AUTH_TOKEN_LEN, &authToken[0], authToken.size()) != EOK) {
        LOG_ERROR("param token copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    param.userId = userId;
    param.credentialId = credentialId;
    CredentialInfoHal credentialInfoHal;
    int32_t ret = DeleteCredentialFunc(param, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("delete failed");
        GlobalUnLock();
        return ret;
    }
    if (memcpy_s(&credentialInfo, sizeof(CredentialInfo), &credentialInfoHal, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t QueryCredential(int32_t userId, uint32_t authType, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("start");
    GlobalLock();
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = QueryCredentialFunc(userId, authType, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        GlobalUnLock();
        return ret;
    }
    for (int i = 0; i < num; i++) {
        CredentialInfo credentialInfo;
        if (memcpy_s(&credentialInfo, sizeof(CredentialInfo),
            &credentialInfoHals[i], sizeof(CredentialInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(credentialInfoHals);
            credentialInfos.clear();
            GlobalUnLock();
            return RESULT_BAD_COPY;
        }
        credentialInfos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t GetSecureUid(int32_t userId, uint64_t &secureUid, std::vector<EnrolledInfo> &enrolledInfos)
{
    LOG_INFO("start");
    GlobalLock();
    EnrolledInfoHal *enrolledInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = GetUserSecureUidFunc(userId, &secureUid, &enrolledInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get user secureUid failed");
        GlobalUnLock();
        return ret;
    }
    for (int i = 0; i < num; i++) {
        EnrolledInfo enrolledInfo;
        if (memcpy_s(&enrolledInfo, sizeof(EnrolledInfo), &enrolledInfoHals[i], sizeof(EnrolledInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(enrolledInfoHals);
            enrolledInfos.clear();
            GlobalUnLock();
            return RESULT_BAD_COPY;
        }
        enrolledInfos.push_back(enrolledInfo);
    }
    free(enrolledInfoHals);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t DeleteUserEnforce(int32_t userId, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("start");
    GlobalLock();
    CredentialInfoHal *credentialInfoHals = nullptr;
    uint32_t num = 0;
    int32_t ret = DeleteUserInfo(userId, &credentialInfoHals, &num);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("query credential failed");
        GlobalUnLock();
        return ret;
    }
    RefreshValidTokenTime();
    for (int i = 0; i < num; i++) {
        CredentialInfo credentialInfo;
        if (memcpy_s(&credentialInfo, sizeof(CredentialInfo),
            &credentialInfoHals[i], sizeof(CredentialInfoHal)) != EOK) {
            LOG_ERROR("credentialInfo copy failed");
            free(credentialInfoHals);
            credentialInfos.clear();
            GlobalUnLock();
            return RESULT_BAD_COPY;
        }
        credentialInfos.push_back(credentialInfo);
    }
    free(credentialInfoHals);
    GlobalUnLock();
    return RESULT_SUCCESS;
}

int32_t DeleteUser(int32_t userId, std::vector<uint8_t> authToken, std::vector<CredentialInfo> &credentialInfos)
{
    LOG_INFO("start");
    GlobalLock();
    authToken.resize(sizeof(UserAuthTokenHal));
    if (authToken.size() != sizeof(UserAuthTokenHal)) {
        LOG_ERROR("authToken is invalid");
        GlobalUnLock();
        return RESULT_BAD_PARAM;
    }
    UserAuthTokenHal authTokenStruct;
    if (memcpy_s(&authTokenStruct, sizeof(UserAuthTokenHal), &authToken[0], authToken.size()) != EOK) {
        LOG_ERROR("authTokenStruct copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    uint64_t challenge;
    int32_t ret = GetChallenge(&challenge);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("get challenge failed");
        GlobalUnLock();
        return ret;
    }
    if (challenge != authTokenStruct.challenge || !IsValidTokenTime(authTokenStruct.time) ||
        UserAuthTokenVerify(&authTokenStruct) != RESULT_SUCCESS) {
        LOG_ERROR("verify token failed");
        GlobalUnLock();
        return RESULT_BAD_SIGN;
    }
    GlobalUnLock();
    return DeleteUserEnforce(userId, credentialInfos);
}

int32_t UpdateCredential(std::vector<uint8_t> enrollToken, uint64_t &credentialId, CredentialInfo &deletedCredential)
{
    LOG_INFO("start");
    GlobalLock();
    if (enrollToken.size() != sizeof(CoAuth::ScheduleToken)) {
        LOG_ERROR("enrollToken is invalid");
        GlobalUnLock();
        return RESULT_BAD_PARAM;
    }
    uint8_t enrollTokenIn[sizeof(ScheduleTokenHal)];
    if (memcpy_s(enrollTokenIn, sizeof(ScheduleTokenHal), &enrollToken[0], enrollToken.size()) != EOK) {
        LOG_ERROR("enrollToken copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    CredentialInfoHal credentialInfoHal;
    int32_t ret = UpdateCredentialFunc(enrollTokenIn, static_cast<uint32_t>(sizeof(ScheduleTokenHal)),
        &credentialId, &credentialInfoHal);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("update failed");
        GlobalUnLock();
        return ret;
    }
    RefreshValidTokenTime();
    if (memcpy_s(&deletedCredential, sizeof(CredentialInfo), &credentialInfoHal, sizeof(CredentialInfoHal)) != EOK) {
        LOG_ERROR("copy failed");
        GlobalUnLock();
        return RESULT_BAD_COPY;
    }
    GlobalUnLock();
    return RESULT_SUCCESS;
}
} // Hal
} // UserIDM
} // UserIAM
} // OHOS
