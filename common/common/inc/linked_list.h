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

#ifndef COMMON_LINKED_LIST_H
#define COMMON_LINKED_LIST_H

#include "stdbool.h"
#include "stdint.h"
#include "defines.h"

typedef void (*DESTROY_DATA_FUNC)(void *data);
typedef bool (*MATCH_FUNC)(void *data, void *condition);
typedef bool (*HANDLE_DATA_FUNC)(void *data, void *arg);

typedef struct LinkedListNode {
    void *data;
    struct LinkedListNode *next;
} LinkedListNode;

typedef struct LinkedListIterator {
    LinkedListNode *current;
    bool (*hasNext)(struct LinkedListIterator *iterator);
    void *(*next)(struct LinkedListIterator *iterator);
} LinkedListIterator;

typedef struct LinkedList {
    uint32_t size;
    LinkedListNode *head;
    DESTROY_DATA_FUNC destroyDataFunc;
    uint32_t (*getSize)(struct LinkedList *list);
    ResultCode (*insert)(struct LinkedList *list, void *data);
    ResultCode (*remove)(struct LinkedList *list, void *condition, MATCH_FUNC matchFunc, bool destroyNode);
    LinkedListIterator *(*createIterator)(struct LinkedList *list);
    void (*destroyIterator)(LinkedListIterator *iterator);
} LinkedList;

LinkedList *CreateLinkedList(DESTROY_DATA_FUNC destroyDataFunc);
void DestroyLinkedList(LinkedList *list);

#endif
