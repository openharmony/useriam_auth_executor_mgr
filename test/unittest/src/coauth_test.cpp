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

#include <gtest/gtest.h>
#include "coauth_test.h"


using namespace testing::ext;
namespace OHOS {
namespace UserIAM {
namespace CoAuth {
class CoAuthTest : public testing::Test {
public:
    static void SetUpTestCase(void);

    static void TearDownTestCase(void);

    void SetUp();

    void TearDown();
};

void CoAuthTest::SetUpTestCase(void)
{
}

void CoAuthTest::TearDownTestCase(void)
{
}

void CoAuthTest::SetUp()
{
}

void CoAuthTest::TearDown()
{
}

/**
 * @tc.name: UseriamUtTest001
 * @tc.desc: Test AuthType(PIN).
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest001, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest001 start");
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    executorInfo->SetAuthType(PIN);
    executorInfo->SetAuthAbility(1);
    executorInfo->SetExecutorSecLevel(ESL0);
    executorInfo->SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo->SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo->SetDeviceId(deviceId);
    class MyExecutorCallback : public AuthResPool::ExecutorCallback {
    public:
        virtual ~MyExecutorCallback() {};
        void OnMessengerReady(const sptr<AuthResPool::IExecutorMessenger> &messenger)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnMessengerReady.");
            return;
        }
        int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                    std::shared_ptr<AuthResPool::AuthAttributes> commandAttrs)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnBeginExecute.");
            return SUCCESS;
        }
        int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> consumerAttr)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnEndExecute.");
            return SUCCESS;
        }
        int32_t OnSetProperty(std::shared_ptr<AuthResPool::AuthAttributes> properties)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnSetProperty.");
            return SUCCESS;
        }
        int32_t OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
                              std::shared_ptr<AuthResPool::AuthAttributes> values)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnGetProperty.");
            return SUCCESS;
        }
    };
    std::shared_ptr<AuthResPool::ExecutorCallback> callback = std::make_shared<MyExecutorCallback>();
    uint64_t ret = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
    EXPECT_LE(10000, ret);
}


/**
 * @tc.name: UseriamUtTest002
 * @tc.desc: Test empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest002, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest002 start");
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    executorInfo->SetAuthType(PIN);
    executorInfo->SetAuthAbility(1);
    executorInfo->SetExecutorSecLevel(ESL0);
    executorInfo->SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo->SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo->SetDeviceId(deviceId);
    std::shared_ptr<AuthResPool::ExecutorCallback> callback = nullptr;
    uint64_t ret = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
    EXPECT_LE(FAIL, ret);
}
/**
 * @tc.name: UseriamUtTest003
 * @tc.desc: Test AuthType(FACE).
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest003, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest003 start");
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    executorInfo->SetAuthType(FACE);
    executorInfo->SetAuthAbility(1);
    executorInfo->SetExecutorSecLevel(ESL0);
    executorInfo->SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo->SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo->SetDeviceId(deviceId);
    class MyExecutorCallback : public AuthResPool::ExecutorCallback {
    public:
        virtual ~MyExecutorCallback() {};
        void OnMessengerReady(const sptr<AuthResPool::IExecutorMessenger> &messenger)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnMessengerReady.");
            return;
        }
        int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                    std::shared_ptr<AuthResPool::AuthAttributes> commandAttrs)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnBeginExecute.");
            return SUCCESS;
        }
        int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> consumerAttr)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnEndExecute.");
            return SUCCESS;
        }
        int32_t OnSetProperty(std::shared_ptr<AuthResPool::AuthAttributes> properties)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnSetProperty.");
            return SUCCESS;
        }
        int32_t OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
                              std::shared_ptr<AuthResPool::AuthAttributes> values)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnGetProperty.");
            return SUCCESS;
        }
    };
    std::shared_ptr<AuthResPool::ExecutorCallback> callback = std::make_shared<MyExecutorCallback>();
    uint64_t ret = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
    EXPECT_LE(10000, ret);
}

/**
 * @tc.name: UseriamUtTest004
 * @tc.desc: Test publicKey error length.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest004, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest004 start");
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = std::make_shared<AuthResPool::AuthExecutor>();
    executorInfo->SetAuthType(FACE);
    executorInfo->SetAuthAbility(1);
    executorInfo->SetExecutorSecLevel(ESL0);
    executorInfo->SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(10, '1');
    executorInfo->SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo->SetDeviceId(deviceId);
    class MyExecutorCallback : public AuthResPool::ExecutorCallback {
    public:
        virtual ~MyExecutorCallback() {};
        void OnMessengerReady(const sptr<AuthResPool::IExecutorMessenger> &messenger)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnMessengerReady.");
            return;
        }
        int32_t OnBeginExecute(uint64_t scheduleId, std::vector<uint8_t> &publicKey,
                                    std::shared_ptr<AuthResPool::AuthAttributes> commandAttrs)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnBeginExecute.");
            return SUCCESS;
        }
        int32_t OnEndExecute(uint64_t scheduleId, std::shared_ptr<AuthResPool::AuthAttributes> consumerAttr)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnEndExecute.");
            return SUCCESS;
        }
        int32_t OnSetProperty(std::shared_ptr<AuthResPool::AuthAttributes> properties)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnSetProperty.");
            return SUCCESS;
        }
        int32_t OnGetProperty(std::shared_ptr<AuthResPool::AuthAttributes> conditions,
                              std::shared_ptr<AuthResPool::AuthAttributes> values)override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyExecutorCallback OnGetProperty.");
            return SUCCESS;
        }
    };
    std::shared_ptr<AuthResPool::ExecutorCallback> callback = std::make_shared<MyExecutorCallback>();
    uint64_t ret = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
    EXPECT_LE(0, ret);
}

/**
 * @tc.name: UseriamUtTest005
 * @tc.desc: Test empty executorInfo and empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest005, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest005 start");
    std::shared_ptr<AuthResPool::AuthExecutor> executorInfo = nullptr;
    std::shared_ptr<AuthResPool::ExecutorCallback> callback = nullptr;
    uint64_t ret = AuthResPool::AuthExecutorRegistry::GetInstance().Register(executorInfo, callback);
    EXPECT_EQ(FAIL, ret);
}

/**
 * @tc.name: UseriamUtTest006
 * @tc.desc: Test AuthType(PIN).
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest006, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest006 start");
    AuthResPool::AuthExecutor executorInfo;
    executorInfo.SetAuthType(PIN);
    executorInfo.SetAuthAbility(1);
    executorInfo.SetExecutorSecLevel(ESL0);
    executorInfo.SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo.SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo.SetDeviceId(deviceId);

    class MyQueryCallback : public AuthResPool::QueryCallback {
    public:
        virtual ~MyQueryCallback() {};
        virtual void OnResult(uint32_t resultCode) override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyQueryCallback OnResult.");
            return;
        }
    };
    std::shared_ptr<AuthResPool::QueryCallback> callback = std::make_shared<MyQueryCallback>();
    AuthResPool::AuthExecutorRegistry::GetInstance().QueryStatus(executorInfo, callback);
    SUCCEED();
}

/**
 * @tc.name: UseriamUtTest007
 * @tc.desc: Test empty executorInfo and empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest007, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest007 start");
    AuthResPool::AuthExecutor executorInfo;
    std::shared_ptr<AuthResPool::QueryCallback> callback = nullptr;
    AuthResPool::AuthExecutorRegistry::GetInstance().QueryStatus(executorInfo, callback);
    SUCCEED();
}

/**
 * @tc.name: UseriamUtTest008
 * @tc.desc: Test AuthType(FACE).
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest008, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest008 start");
    AuthResPool::AuthExecutor executorInfo;
    executorInfo.SetAuthType(FACE);
    executorInfo.SetAuthAbility(1);
    executorInfo.SetExecutorSecLevel(ESL0);
    executorInfo.SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo.SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo.SetDeviceId(deviceId);

    class MyQueryCallback : public AuthResPool::QueryCallback {
    public:
        virtual ~MyQueryCallback() {};
        virtual void OnResult(uint32_t resultCode) override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyQueryCallback OnResult.");
            return;
        }
    };
    std::shared_ptr<AuthResPool::QueryCallback> callback = std::make_shared<MyQueryCallback>();
    AuthResPool::AuthExecutorRegistry::GetInstance().QueryStatus(executorInfo, callback);
    SUCCEED();
}
/**
 * @tc.name: UseriamUtTest009
 * @tc.desc: Test empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest009, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest009 start");
    AuthResPool::AuthExecutor executorInfo;
    executorInfo.SetAuthType(FACE);
    executorInfo.SetAuthAbility(1);
    executorInfo.SetExecutorSecLevel(ESL0);
    executorInfo.SetExecutorType(TYPE_CO_AUTH);

    std::vector<uint8_t> publicKey(32, '1');
    executorInfo.SetPublicKey(publicKey);

    std::vector<uint8_t> deviceId;
    deviceId.push_back('2');
    executorInfo.SetDeviceId(deviceId);

    std::shared_ptr<AuthResPool::QueryCallback> callback = nullptr;
    AuthResPool::AuthExecutorRegistry::GetInstance().QueryStatus(executorInfo, callback);
    SUCCEED();
}
/**
 * @tc.name: UseriamUtTest010
 * @tc.desc: Test empty authInfo and empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest010, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest010 start");
    AuthInfo authInfo;
    std::shared_ptr<CoAuthCallback> callback = nullptr;
    CoAuth::GetInstance().coAuth(1, authInfo, callback);
    SUCCEED();
}

/**
 * @tc.name: UseriamUtTest011
 * @tc.desc: Test normal value.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest011, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest011 start");
    AuthInfo authInfo;
    std::string value = "packagedemo";
    authInfo.SetPkgName(value);
    authInfo.SetCallerUid(10000);
    class MyCoAuthCallback : public CoAuthCallback {
    public:
        virtual ~MyCoAuthCallback() {};
        virtual void OnFinish(uint32_t resultCode, std::vector<uint8_t> &scheduleToken) override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyCoAuthCallback OnFinish.");
            return;
        }
        virtual void OnAcquireInfo(uint32_t acquire) override {
            COAUTH_HILOGE(MODULE_SERVICE, "MyCoAuthCallback OnAcquireInfo.");
            return;
        }
    };
    std::shared_ptr<CoAuthCallback> callback = std::make_shared<MyCoAuthCallback>();
    CoAuth::GetInstance().coAuth(1, authInfo, callback);
    SUCCEED();
}
/**
 * @tc.name: UseriamUtTest012
 * @tc.desc: Test empty callback.
 * @tc.type: FUNC
 */
HWTEST_F(CoAuthTest, UseriamUtTest012, TestSize.Level0)
{
    COAUTH_HILOGD(MODULE_INNERKIT, "UseriamUtTest012 start");
    AuthInfo authInfo;
    std::string value = "packagedemo";
    authInfo.SetPkgName(value);
    authInfo.SetCallerUid(10000);
    std::shared_ptr<CoAuthCallback> callback = nullptr;
    CoAuth::GetInstance().coAuth(1, authInfo, callback);
    SUCCEED();
}

HWTEST_F(CoAuthTest, UseriamUtTest013, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest013 enter.");
    uint64_t scheduleId = 0;
    EXPECT_EQ(0, CoAuth::GetInstance().Cancel(scheduleId));

    scheduleId = 1;
    EXPECT_EQ(0, CoAuth::GetInstance().Cancel(scheduleId));
}

HWTEST_F(CoAuthTest, UseriamUtTest014, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest014 enter.");
    AuthResPool::AuthAttributes conditions;
    conditions.SetUint32Value(AUTH_TYPE, FACE);
    conditions.SetBoolValue(AUTH_CONTROLLER, 0);
    conditions.SetUint32Value(AUTH_SCHEDULE_MODE, 1);
    conditions.SetUint64Value(AUTH_SESSION_ID, 1);

    std::vector<uint64_t> val1;
    val1.push_back(1);
    conditions.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, val1);

    std::vector<uint8_t> val2;
    val2.push_back('5');
    conditions.SetUint8ArrayValue(AUTH_CALLER_NAME, val2);

    class MySetPropCallback : public SetPropCallback {
    public:

        virtual ~MySetPropCallback() {};
        void OnResult(uint32_t result, std::vector<uint8_t> &extraInfo)override
        {
            COAUTH_HILOGE(MODULE_SERVICE, "MySetPropCallback OnResult.");
            return;
        }

    };
    std::shared_ptr<SetPropCallback> callback = std::make_shared<MySetPropCallback>();
    CoAuth::GetInstance().SetExecutorProp(conditions, callback);
    sleep(5);
    SUCCEED();
}

HWTEST_F(CoAuthTest, UseriamUtTest015, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest015 enter.");
    AuthResPool::AuthAttributes conditions;
    conditions.SetUint32Value(AUTH_TYPE, FACE);
    conditions.SetBoolValue(AUTH_CONTROLLER, 0);
    conditions.SetUint32Value(AUTH_SCHEDULE_MODE, 1);
    conditions.SetUint64Value(AUTH_SESSION_ID, 1);

    std::vector<uint64_t> val1;
    val1.push_back(1);
    conditions.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, val1);

    std::vector<uint8_t> val2;
    val2.push_back('5');
    conditions.SetUint8ArrayValue(AUTH_CALLER_NAME, val2);
    std::shared_ptr<SetPropCallback> callback = nullptr;
    CoAuth::GetInstance().SetExecutorProp(conditions, callback);
    sleep(5);
    SUCCEED();
}

HWTEST_F(CoAuthTest, UseriamUtTest016, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest016 enter.");
    AuthResPool::AuthAttributes conditions;
    conditions.SetUint32Value(AUTH_TYPE, FACE);
    conditions.SetBoolValue(AUTH_CONTROLLER, 0);
    conditions.SetUint32Value(AUTH_SCHEDULE_MODE, 1);
    conditions.SetUint64Value(AUTH_SESSION_ID, 1);

    std::vector<uint64_t> val1;
    val1.push_back(1);
    conditions.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, val1);

    std::vector<uint8_t> val2;
    val2.push_back('5');
    conditions.SetUint8ArrayValue(AUTH_CALLER_NAME, val2);

    std::shared_ptr<AuthResPool::AuthAttributes> values = std::make_shared<AuthResPool::AuthAttributes>();
    int32_t ret = CoAuth::GetInstance().GetExecutorProp(conditions, values);
    sleep(5);
    EXPECT_EQ(0, ret);
}

HWTEST_F(CoAuthTest, UseriamUtTest017, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest017 enter.");
    AuthResPool::AuthAttributes conditions;
    conditions.SetBoolValue(AUTH_CONTROLLER, 0);
    conditions.SetUint32Value(AUTH_SCHEDULE_MODE, 1);
    conditions.SetUint64Value(AUTH_SESSION_ID, 1);

    std::vector<uint64_t> val1;
    val1.push_back(1);
    conditions.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, val1);

    std::vector<uint8_t> val2;
    val2.push_back('5');
    conditions.SetUint8ArrayValue(AUTH_CALLER_NAME, val2);

    std::shared_ptr<AuthResPool::AuthAttributes> values = nullptr;
    int32_t ret = CoAuth::GetInstance().GetExecutorProp(conditions, values);
    sleep(5);
    EXPECT_EQ(1, ret);
}

HWTEST_F(CoAuthTest, UseriamUtTest018, TestSize.Level0)
{
    COAUTH_HILOGE(MODULE_SERVICE, "UseriamUtTest018 enter.");
    AuthResPool::AuthAttributes conditions;
    conditions.SetUint32Value(AUTH_TYPE, PIN);
    conditions.SetBoolValue(AUTH_CONTROLLER, 0);
    conditions.SetUint32Value(AUTH_SCHEDULE_MODE, 1);
    conditions.SetUint64Value(AUTH_SESSION_ID, 1);

    std::vector<uint64_t> val1;
    val1.push_back(1);
    conditions.SetUint64ArrayValue(AUTH_TEMPLATE_ID_LIST, val1);

    std::vector<uint8_t> val2;
    val2.push_back('5');
    conditions.SetUint8ArrayValue(AUTH_CALLER_NAME, val2);

    std::shared_ptr<AuthResPool::AuthAttributes> values = std::make_shared<AuthResPool::AuthAttributes>();
    int32_t ret = CoAuth::GetInstance().GetExecutorProp(conditions, values);
    sleep(5);
    EXPECT_EQ(0, ret);
}
}
}
}