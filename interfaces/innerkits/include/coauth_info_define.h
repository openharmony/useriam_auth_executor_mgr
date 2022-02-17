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

#ifndef COAUTH_INFO_DEFINE_H
#define COAUTH_INFO_DEFINE_H

#include "parcel.h"

namespace OHOS {
namespace UserIAM {
/* enums define */
enum AuthAttributeType {
    /* Root tag */
    AUTH_ROOT = 100000,
    /* Result code */
    AUTH_RESULT_CODE = 100001,
    /* Tag of signature data in TLV */
    AUTH_SIGNATURE = 100004,
    /* Identify mode */
    AUTH_IDENTIFY_MODE = 100005,
    /* Tag of templateId data in TLV */
    AUTH_TEMPLATE_ID = 100006,
    /* Tag of templateId list data in TLV */
    AUTH_TEMPLATE_ID_LIST = 100007,
    /* Expected attribute, tag of remain count in TLV */
    AUTH_REMAIN_COUNT = 100009,
    /* Remain time */
    AUTH_REMAIN_TIME = 100010,
    /* Session id, required when decode in C */
    AUTH_SESSION_ID = 100014,
    /* Package name */
    AUTH_CALLER_NAME = 100015,
    /* Schedule version */
    AUTH_SCHEDULE_VERSION = 100016,
    /* Tag of lock out template in TLV */
    AUTH_LOCK_OUT_TEMPLATE = 100018,
    /* Tag of unlock template in TLV */
    AUTH_UNLOCK_TEMPLATE = 100019,
    /* Tag of data */
    AUTH_DATA = 100020,
    /* Tag of auth subType */
    AUTH_SUBTYPE = 100021,
    /* Tag of auth schedule mode */
    AUTH_SCHEDULE_MODE = 100022,
    /* Tag of property */
    AUTH_PROPERTY_MODE = 100023,
    /* Tag of auth type */
    AUTH_TYPE = 100024,
    /* Tag of cred id */
    AUTH_CREDENTIAL_ID = 100025,
    /* Controller */
    AUTH_CONTROLLER = 100026,
    /* calleruid */
    AUTH_CALLER_UID = 100027,
    /* result */
    AUTH_RESULT = 100028,
    /* algorithm setinfo */
    ALGORITHM_INFO
};

enum AuthType {
    /* Authentication type pin */
    PIN = 1,
    /* Authentication type face */
    FACE = 2
};

enum AuthAbility {
    /* Executor authentication ability six number pin */
    PIN_SIX = 1,
    /* Executor authentication ability self defined number pin */
    PIN_NUMBER = 2,
    /* Executor authentication ability mixed pin */
    PIN_MIXED = 4,
    /* Executor authentication ability 2D face */
    FACE_2D = 1,
    /* Executor authentication ability 3D face */
    FACE_3D = 2
};

/* Safety level of actuator */
enum ExecutorSecureLevel {
    /* Executor without access control */
    ESL0 = 0,
    /* Executor with access control */
    ESL1 = 1,
    /* Executor in secure hardware */
    ESL2 = 2,
    /* Executor in high secure hardware */
    ESL3 = 3
};

enum ExecutorType {
    /* Type of coauth */
    TYPE_CO_AUTH = 0,
    /* Type of executor collector */
    TYPE_COLLECTOR = 1,
    /* Type of executor verifier */
    TYPE_VERIFIER = 2,
    /* Type of executor all in one */
    TYPE_ALL_IN_ONE = 3
};

enum ResultCode {
    /**
     * Indicates that authentication is success or ability is supported.
     */
    SUCCESS = 0,
    /**
     * Indicates the authenticator fails to identify user.
     */
    FAIL = 1,
    /**
     * Indicates other errors.
     */
    GENERAL_ERROR = 2,
    /**
     * Indicates that authentication has been canceled.
     */
    CANCELED = 3,
    /**
     * Indicates that authentication has timed out.
     */
    TIMEOUT = 4,
    /**
     * Indicates that this authentication type is not supported.
     */
    TYPE_NOT_SUPPORT = 5,
    /**
     * Indicates that the authentication trust level is not supported.
     */
    TRUST_LEVEL_NOT_SUPPORT = 6,
    /**
     * Indicates that the authentication task is busy. Wait for a few seconds and try again.
     */
    BUSY = 7,
    /**
     * Indicates incorrect parameters.
     */
    INVALID_PARAMETERS = 8,
    /**
     * Indicates that the authenticator is locked.
     */
    LOCKED = 9,
    /**
     * Indicates that the user has not enrolled the authenticator.
     */
    NOT_ENROLLED = 10
};

const uint64_t INVALID_EXECUTOR_ID = 0;
const std::string REGISTER_NOTIFICATION = "EXECUTOR_REGISTER_NOTIFICATION";
} // namespace UserIAM
} // namespace OHOS
#endif // COAUTH_INFO_DEFINE_H
