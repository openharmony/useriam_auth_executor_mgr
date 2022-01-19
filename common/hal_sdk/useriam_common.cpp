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

#include "useriam_common.h"

extern "C" {
#include <sys/stat.h>
#include <unistd.h>

#include "pool.h"
#include "idm_database.h"
#include "coauth.h"
#include "context_manager.h"
#include "adaptor_log.h"
#include "lock.h"
}

namespace OHOS {
namespace UserIAM {
namespace Common {
static const char *IDM_USER_FOLDER = "/data/useriam";
static bool g_isInitUserIAM = false;

int32_t Init()
{
    GlobalLock();
    LOG_INFO("check useriam folder exist or init it.");
    if (IDM_USER_FOLDER && access(IDM_USER_FOLDER, 0) == -1) {
        mkdir(IDM_USER_FOLDER, S_IRWXU);
    }
    if (InitUserAuthContextList() != RESULT_SUCCESS) {
        LOG_ERROR("init user auth failed");
        goto FAIL;
    }
    if (InitResorcePool() != RESULT_SUCCESS) {
        LOG_ERROR("init resorce pool failed");
        goto FAIL;
    }
    if (InitUserInfoList() != RESULT_SUCCESS) {
        LOG_ERROR("init user info failed");
        goto FAIL;
    }
    if (InitCoAuth() != RESULT_SUCCESS) {
        LOG_ERROR("init user auth failed");
        goto FAIL;
    }
    g_isInitUserIAM = true;
    GlobalUnLock();
    return RESULT_SUCCESS;

FAIL:
    Close();
    GlobalUnLock();
    return RESULT_UNKNOWN;
}

int32_t Close()
{
    GlobalLock();
    DestoryUserAuthContextList();
    DestoryCoAuth();
    DestroyUserInfoList();
    DestroyResorcePool();
    g_isInitUserIAM = false;
    GlobalUnLock();
    return RESULT_SUCCESS;
}

bool IsIAMInited()
{
    return g_isInitUserIAM;
}
} // Common
} // UserIAM
} // OHOS