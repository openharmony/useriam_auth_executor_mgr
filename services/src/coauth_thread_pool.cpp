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
#include "coauth_thread_pool.h"

namespace OHOS {
namespace UserIAM {
namespace CoAuth {
const int32_t COAUTH_THREAD_NUM = 20;
std::mutex CoAuthThreadPool::mutex_;
std::shared_ptr<CoAuthThreadPool> CoAuthThreadPool::instance_ = nullptr;
CoAuthThreadPool::CoAuthThreadPool()
{
    Start(COAUTH_THREAD_NUM);
}

CoAuthThreadPool::~CoAuthThreadPool()
{
    Stop();
}

std::shared_ptr<CoAuthThreadPool> CoAuthThreadPool::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> lock_l(mutex_);
        if (instance_ == nullptr) {
            instance_ = std::make_shared<CoAuthThreadPool>();
        }
    }
    return instance_;
}
} // namespace CoAuth
} // namespace UserIAM
} // namespace OHOS