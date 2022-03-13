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

#ifndef COAUTH_HILOG_WRAPPER_H
#define COAUTH_HILOG_WRAPPER_H

#define CONFIG_HILOG
#ifdef CONFIG_HILOG
#include "hilog/log.h"
namespace OHOS {
namespace UserIAM {
#define FILENAME           (__builtin_strrchr(__FILE__, '/') ? __builtin_strrchr(__FILE__, '/') + 1 : __FILE__)
#define FORMATTED(fmt, ...)    "[%{public}s] %{public}s# " fmt, FILENAME, __FUNCTION__, ##__VA_ARGS__

#ifdef COAUTH_HILOGF
#undef COAUTH_HILOGF
#endif

#ifdef COAUTH_HILOGE
#undef COAUTH_HILOGE
#endif

#ifdef COAUTH_HILOGW
#undef COAUTH_HILOGW
#endif

#ifdef COAUTH_HILOGI
#undef COAUTH_HILOGI
#endif

#ifdef COAUTH_HILOGD
#undef COAUTH_HILOGD
#endif

// param of log interface, such as COAUTH_HILOGF.
enum CoauthSubModule {
    MODULE_INNERKIT = 0,
    MODULE_SERVICE,
    MODULE_COMMON,
    MODULE_JS_NAPI,
    COAUTH_MODULE_BUTT,
};

// 0xD002900: subsystem:distributeddatamgr module:distributedgallery, 8 bits reserved.
static constexpr unsigned int BASE_COAUTH_DOMAIN_ID = 0xD002910;

enum CoauthDomainId {
    COAUTH_INNERKIT_DOMAIN = BASE_COAUTH_DOMAIN_ID + MODULE_INNERKIT,
    COAUTH_SERVICE_DOMAIN,
    COMMON_DOMAIN,
    COAUTH_JS_NAPI,
    COAUTH_BUTT,
};

static constexpr OHOS::HiviewDFX::HiLogLabel COAUTH_LABEL[COAUTH_MODULE_BUTT] = {
    {LOG_CORE, COAUTH_INNERKIT_DOMAIN, "CoAuth"},
    {LOG_CORE, COAUTH_SERVICE_DOMAIN, "CoAuthService"},
    {LOG_CORE, COMMON_DOMAIN, "CoAuthCommon"},
    {LOG_CORE, COAUTH_JS_NAPI, "CoAuthJSNAPI"},
};

// In order to improve performance, do not check the module range.
// Besides, make sure module is less than COAUTH_MODULE_BUTT.
#define COAUTH_HILOGF(module, ...) (void)OHOS::HiviewDFX::HiLog::Fatal(COAUTH_LABEL[module], FORMATTED(__VA_ARGS__))
#define COAUTH_HILOGE(module, ...) (void)OHOS::HiviewDFX::HiLog::Error(COAUTH_LABEL[module], FORMATTED(__VA_ARGS__))
#define COAUTH_HILOGW(module, ...) (void)OHOS::HiviewDFX::HiLog::Warn(COAUTH_LABEL[module], FORMATTED(__VA_ARGS__))
#define COAUTH_HILOGI(module, ...) (void)OHOS::HiviewDFX::HiLog::Info(COAUTH_LABEL[module], FORMATTED(__VA_ARGS__))
#define COAUTH_HILOGD(module, ...) (void)OHOS::HiviewDFX::HiLog::Debug(COAUTH_LABEL[module], FORMATTED(__VA_ARGS__))
} // namespace UserIAM
} // namespace OHOS

#else

#define COAUTH_HILOGF(...)
#define COAUTH_HILOGE(...)
#define COAUTH_HILOGW(...)
#define COAUTH_HILOGI(...)
#define COAUTH_HILOGD(...)

#endif // CONFIG_HILOG

#endif // COAUTH_HILOG_WRAPPER_H
