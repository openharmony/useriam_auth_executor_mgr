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

#include "bitwise_operation.h"

uint64_t GetUint64(uint32_t high, uint32_t low)
{
    uint64_t tmpHigh = high;
    // Combine two 32-bit data into one 64-bit data
    return ((tmpHigh << 32) | low);
}

void SplitUint64(uint64_t number, uint32_t *high, uint32_t *low)
{
    // Combine 64-bit data into two 64-bit data
    *low = number & 0xffffffff;
    *high = (number >> sizeof(uint32_t)) & 0xffffffff;
}