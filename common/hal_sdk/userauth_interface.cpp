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

#include "adaptor_log.h"
#include "user_auth_funcs.h"
#include "coauth_interface.h"
#include "auth_level.h"

namespace OHOS {
namespace UserIAM {
namespace UserAuth {

int32_t GenerateSolution(AuthSolution param, std::vector<uint64_t> &scheduleIds)
{
    LOG_INFO("begin");
    uint64_t *scheduleIdsGet = nullptr;
    uint32_t scheduleIdNum = 0;
    AuthSolutionHal solutionIn;
    param.userId = 0;
    LOG_ERROR("contextId = %{public}lld, userId = %{public}d", param.contextId, param.userId);
    if (memcpy_s(&solutionIn, sizeof(AuthSolutionHal), &param, sizeof(AuthSolution)) != EOK) {
        LOG_ERROR("copy failed");
        return RESULT_BAD_COPY;
    }
    int32_t ret = GenerateSolutionFunc(solutionIn, &scheduleIdsGet, &scheduleIdNum);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("generate solution failed");
        return ret;
    }
    for (uint32_t i = 0; i < scheduleIdNum; i++) {
        scheduleIds.push_back(scheduleIdsGet[i]);
    }
    free(scheduleIdsGet);
    return RESULT_SUCCESS;
}

int32_t RequestAuthResult(uint64_t contextId, std::vector<uint8_t> &scheduleToken, UserAuthToken &authToken,
    std::vector<uint64_t> &scheduleIds)
{
    LOG_INFO("begin");
    if (scheduleToken.size() != sizeof(CoAuth::ScheduleToken)) {
        LOG_ERROR("param is invalid");
        return RESULT_BAD_PARAM;
    }
    Buffer *scheduleTokenBuffer = CreateBufferByData(&scheduleToken[0], scheduleToken.size());
    if (scheduleTokenBuffer == nullptr) {
        LOG_ERROR("scheduleTokenBuffer is null");
        return RESULT_NO_MEMORY;
    }
    UserAuthTokenHal authTokenHal;
    uint64_t *scheduleIdsGet = nullptr;
    uint32_t scheduleIdNum = 0;
    int32_t ret = RequestAuthResultFunc(contextId, scheduleTokenBuffer, &authTokenHal, &scheduleIdsGet, &scheduleIdNum);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("execute func failed");
        DestoryBuffer(scheduleTokenBuffer);
        return ret;
    }
    for (uint32_t i = 0; i < scheduleIdNum; i++) {
        scheduleIds.push_back(scheduleIdsGet[i]);
    }
    free(scheduleIdsGet);
    DestoryBuffer(scheduleTokenBuffer);
    return RESULT_SUCCESS;
}

int32_t CancelContext(uint64_t contextId, std::vector<uint64_t> &scheduleIds)
{
    LOG_INFO("begin");
    uint64_t *scheduleIdsGet = nullptr;
    uint32_t scheduleIdNum = 0;
    int32_t ret = CancelContextFunc(contextId, &scheduleIdsGet, &scheduleIdNum);
    if (ret != RESULT_SUCCESS) {
        LOG_ERROR("execute func failed");
        return ret;
    }
    for (uint32_t i = 0; i < scheduleIdNum; i++) {
        scheduleIds.push_back(scheduleIdsGet[i]);
    }
    free(scheduleIdsGet);
    return RESULT_SUCCESS;
}

int32_t GetAuthTrustLevel(int32_t userId, uint32_t authType, uint32_t &authTrustLevel)
{
    LOG_INFO("begin");
    return SingleAuthTrustLevel(userId, authType, &authTrustLevel);
}

}
}
}