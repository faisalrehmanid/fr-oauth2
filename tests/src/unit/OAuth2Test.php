<?php

namespace FRUnitTest\OAuth2;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\OAuth2;

class OAuth2Test extends TestCase
{
    protected static $OAuth2TestAsset;
    protected static $ServiceResponse;
    protected static $ClientsStorage;
    protected static $AccessTokensStorage;
    protected static $RefreshTokensStorage;
    protected static $OAuth2;
    protected static $config;

    /**
     * This method is executed only once per class
     *
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        self::$OAuth2TestAsset = new OAuth2TestAsset();

        self::$ServiceResponse = self::$OAuth2TestAsset->getServiceResponse();
        self::$ClientsStorage = self::$OAuth2TestAsset->getClientsStorage();
        self::$AccessTokensStorage = self::$OAuth2TestAsset->getAccessTokensStorage();
        self::$RefreshTokensStorage = self::$OAuth2TestAsset->getRefreshTokensStorage();
        self::$OAuth2 = self::$OAuth2TestAsset->getOAuth2();
        self::$config = self::$OAuth2TestAsset->getConfig();
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::__construct
     * 
     * @return void
     */
    public function constructor()
    {
        // validate access_token_lifetime
        $invalid_access_token_lifetime = ['', '80', 40];
        foreach ($invalid_access_token_lifetime as $i => $access_token_lifetime) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['access_token_lifetime'] = $access_token_lifetime;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `access_token_lifetime` cannot be empty and must be integer and must be greater than or equal to 60 seconds');
        }

        // validate access_token_length
        $invalid_access_token_length = ['', '128', 16, 256, 60];
        foreach ($invalid_access_token_length as $i => $access_token_length) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['access_token_length'] = $access_token_length;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `access_token_length` cannot be empty and must be integer and must be from 32 to 128 chars and must be divisible by 8');
        }

        // validate refresh_token_lifetime
        $invalid_refresh_token_lifetime = ['', '80', 40];
        foreach ($invalid_refresh_token_lifetime as $i => $refresh_token_lifetime) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['refresh_token_lifetime'] = $refresh_token_lifetime;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `refresh_token_lifetime` cannot be empty and must be integer and must be greater than or equal to 60 seconds');
        }

        // validate refresh_token_length
        $invalid_refresh_token_length = ['', '128', 16, 256, 60];
        foreach ($invalid_refresh_token_length as $i => $refresh_token_length) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['refresh_token_length'] = $refresh_token_length;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `refresh_token_length` cannot be empty and must be integer and must be from 32 to 128 chars and must be divisible by 8');
        }

        $token_types = ['Bearer'];
        $invalid_token_type = ['', 16, true, 'XYZ', 'bearer'];
        foreach ($invalid_token_type as $i => $token_type) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['token_type'] = $token_type;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `token_type` cannot be empty and must be in ' . implode(", ", $token_types));
        }

        $invalid_always_issue_new_refresh_token = ['', 'true'];
        foreach ($invalid_always_issue_new_refresh_token as $i => $always_issue_new_refresh_token) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['always_issue_new_refresh_token'] = $always_issue_new_refresh_token;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `always_issue_new_refresh_token` must be boolean');
        }

        $invalid_grant_types = [
            [''],
            ['  '],
            [' invalid_grant_type '],
            ['client_credentials', 'password', 'invalid'],
            ['passWord']
        ];
        // Supported grant types
        $supported_grant_types = ['client_credentials', 'password', 'refresh_token'];
        foreach ($invalid_grant_types as $i => $grant_types) {
            $exception = false;
            try {
                // Override $config with invalid value
                $config = self::$config;
                $config['grant_types'] = $grant_types;

                new OAuth2(
                    self::$ServiceResponse,
                    $config,
                    self::$ClientsStorage,
                    self::$AccessTokensStorage,
                    self::$RefreshTokensStorage
                );
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `grant_types` must be from ' . implode(', ', $supported_grant_types));
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::generateUniqueId
     * 
     * @return void
     */
    public function generateUniqueId()
    {
        $test = [
            [
                'length' => 32,
            ],
            [
                'length' => '64',
            ],
            [
                'length' => 128,
            ],
            [
                'length' => '256',
            ],
        ];

        foreach ($test as $i => $param) {
            $token = invokeMethod(
                self::$OAuth2,
                'generateUniqueId',
                [$param['length']]
            );

            $this->assertEquals($param['length'], strlen($token));
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::verifyClientCredentials
     * 
     * @return void
     */
    public function verifyClientCredentials()
    {
        $test = [
            [
                'client_id' => 'invalid-client-id',
                'client_secret' => 'invalid-secret-id',
            ],
            [
                'client_id' => 'client-id-1',
                'client_secret' => 'client-secret-2',
            ],
            [
                'client_id' => ' client-Id-3 ',
                'client_secret' => ' client-Secret-3 ',
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'verifyClientCredentials',
                [$param['client_id'], $param['client_secret']]
            );

            if (in_array($i, [0, 1])) {
                $this->assertEquals(400, @$response['code']);
                $this->assertEquals('error', @$response['status']);
            }

            if (in_array($i, [0]))
                $this->assertEquals('client_not_found', @$response['type']);
            if (in_array($i, [1]))
                $this->assertEquals('invalid_client_credentials', @$response['type']);

            if (in_array($i, [2])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('client_id', @$response['data']);
                $this->assertArrayNotHasKey('client_secret', @$response['data']);
                $this->assertEqualsIgnoringCase(trim($param['client_id']), @$response['data']['client_id']);
            }
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::createAccessToken
     * 
     * @return void
     */
    public function createAccessToken()
    {
        $test = [
            [
                'client_id' => 'client-id-1',
                'user_id' => ''
            ],
            [
                'client_id' => 'client-id-2',
                'user_id' => generateUniqueId(32)
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'createAccessToken',
                [$param['client_id'], $param['user_id']]
            );

            $this->assertEquals(200, @$response['code']);
            $this->assertEquals('success', @$response['status']);
            $this->assertIsArray(@$response['data']);
            $this->assertNotEmpty(@$response['data']);
            $this->assertArrayHasKey('access_token', @$response['data']);
            $this->assertArrayHasKey('expires_in',   @$response['data']);
            $this->assertArrayHasKey('token_type',   @$response['data']);
            $this->assertEquals(self::$config['access_token_length'], strlen(@$response['data']['access_token']));
            $this->assertEquals(self::$config['token_type'], @$response['data']['token_type']);

            self::$AccessTokensStorage->deleteAccessToken(@$response['data']['access_token']);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::createRefreshToken
     * 
     * @return void
     */
    public function createRefreshToken()
    {
        $test = [
            [
                'client_id' => 'client-id-1',
                'user_id' => ''
            ],
            [
                'client_id' => 'client-id-2',
                'user_id' => generateUniqueId(32)
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'createRefreshToken',
                [$param['client_id'], $param['user_id']]
            );

            $this->assertEquals(200, @$response['code']);
            $this->assertEquals('success', @$response['status']);
            $this->assertIsArray(@$response['data']);
            $this->assertNotEmpty(@$response['data']);
            $this->assertArrayHasKey('refresh_token', @$response['data']);
            $this->assertEquals(self::$config['refresh_token_length'], strlen(@$response['data']['refresh_token']));

            self::$RefreshTokensStorage->deleteRefreshToken(@$response['data']['refresh_token']);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::verifyRefreshToken
     * 
     * @return void
     */
    public function verifyRefreshToken()
    {
        // Create valid refresh token
        $refresh_token = generateUniqueId(self::$config['refresh_token_length']);
        self::$RefreshTokensStorage->insertRefreshToken(
            $refresh_token,
            'client-id-1',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('+1 Day'))
        );

        // Create expired refresh token
        $expired_refresh_token = generateUniqueId(self::$config['refresh_token_length']);
        self::$RefreshTokensStorage->insertRefreshToken(
            $expired_refresh_token,
            'client-id-1',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('-1 Second'))
        );

        $test = [
            [
                'client_id' => '  ',
                'refresh_token' => '  ',
            ],
            [
                'client_id' => 'invalid-client-id',
                'refresh_token' => 'invalid-refresh-token',
            ],
            [
                'client_id' => 'client-id-2',
                'refresh_token' => $refresh_token,
            ],
            [
                'client_id' => 'client-id-1',
                'refresh_token' => $expired_refresh_token,
            ],
            [
                'client_id' => 'client-id-1',
                'refresh_token' => $refresh_token,
            ],
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'verifyRefreshToken',
                [$param['client_id'], $param['refresh_token']]
            );

            if (in_array($i, [0, 1])) {
                $this->assertEquals(400, @$response['code']);
                $this->assertEquals('error', @$response['status']);
            }

            if (in_array($i, [0]))
                $this->assertEquals('client_id_refresh_token_required', @$response['type']);
            if (in_array($i, [1]))
                $this->assertEquals('invalid_refresh_token', @$response['type']);
            if (in_array($i, [2]))
                $this->assertEquals('invalid_for_client', @$response['type']);
            if (in_array($i, [3]))
                $this->assertEquals('expired_refresh_token', @$response['type']);

            if (in_array($i, [4])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('client_id', @$response['data']);
                $this->assertArrayHasKey('refresh_token', @$response['data']);
                $this->assertArrayHasKey('user_id', @$response['data']);
                $this->assertArrayHasKey('expired_at', @$response['data']);

                $this->assertEqualsIgnoringCase(trim($param['client_id']), @$response['data']['client_id']);
                $this->assertEqualsIgnoringCase(trim($param['refresh_token']), @$response['data']['refresh_token']);
            }
        }

        self::$RefreshTokensStorage->deleteRefreshToken($refresh_token);
        self::$RefreshTokensStorage->deleteRefreshToken($expired_refresh_token);
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::verifyAccessToken
     * 
     * @return void
     */
    public function verifyAccessToken()
    {
        // Create valid access token
        $access_token = generateUniqueId(self::$config['access_token_length']);
        self::$AccessTokensStorage->insertAccessToken(
            $access_token,
            'client-id-1',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('+1 Hour'))
        );

        // Create expired access token
        $expired_access_token = generateUniqueId(self::$config['access_token_length']);
        self::$AccessTokensStorage->insertAccessToken(
            $expired_access_token,
            'client-id-1',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('-1 Second'))
        );

        $test = [
            [
                'token_type' => '   ',
                'access_token' => '  ',
            ],
            [
                'token_type' => 'invalid-token-type',
                'access_token' => $access_token,
            ],
            [
                'token_type' => self::$config['token_type'],
                'access_token' => 'invalid-access-token',
            ],
            [
                'token_type' => self::$config['token_type'],
                'access_token' => $expired_access_token,
            ],
            [
                'token_type' => self::$config['token_type'],
                'access_token' => $access_token,
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'verifyAccessToken',
                [$param['token_type'], $param['access_token']]
            );

            if (in_array($i, [0, 1, 2])) {
                $this->assertEquals(403, @$response['code']);
                $this->assertEquals('error', @$response['status']);
            }

            if (in_array($i, [0]))
                $this->assertEquals('token_type_access_token_required', @$response['type']);
            if (in_array($i, [1]))
                $this->assertEquals('invalid_token_type', @$response['type']);
            if (in_array($i, [2]))
                $this->assertEquals('invalid_access_token', @$response['type']);
            if (in_array($i, [3])) {
                $this->assertEquals(401, @$response['code']);
                $this->assertEquals('error', @$response['status']);
                $this->assertEquals('expired_access_token', @$response['type']);
            }

            if (in_array($i, [4])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('client_id', @$response['data']);
                $this->assertArrayHasKey('access_token', @$response['data']);
                $this->assertArrayHasKey('user_id', @$response['data']);
                $this->assertArrayHasKey('expired_at', @$response['data']);

                $this->assertEqualsIgnoringCase(trim($param['access_token']), @$response['data']['access_token']);
            }
        }

        self::$AccessTokensStorage->deleteAccessToken($access_token);
        self::$AccessTokensStorage->deleteAccessToken($expired_access_token);
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::token
     * 
     * @return void
     */
    public function token()
    {
        // Create valid refresh token
        $refresh_token = generateUniqueId(self::$config['refresh_token_length']);
        self::$RefreshTokensStorage->insertRefreshToken(
            $refresh_token,
            'client-id-1',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('+1 Day'))
        );

        $test = [
            [
                'grant_type' => 'invalid-grant-type',
                'client_id' => '',
                'client_secret' => '',
                'user_id' => '',
                'refresh_token' => ''
            ],
            [
                'grant_type' => 'client_credentials',
                'client_id' => 'client-id-1',
                'client_secret' => 'invalid-client-secret',
                'user_id' => '',
                'refresh_token' => ''
            ],
            [
                'grant_type' => 'client_credentials',
                'client_id' => ' client-iD-3 ',
                'client_secret' => ' client-sEcret-3 ',
                'user_id' => '',
                'refresh_token' => ''
            ],
            [
                'grant_type' => 'password',
                'client_id' => ' client-iD-3 ',
                'client_secret' => ' client-Secret-3 ',
                'user_id' => '',
                'refresh_token' => ''
            ],
            [
                'grant_type' => 'password',
                'client_id' => ' client-iD-3 ',
                'client_secret' => ' client-Secret-3 ',
                'user_id' => generateUniqueId(32),
                'refresh_token' => ''
            ],
            [
                'grant_type' => 'refresh_token',
                'client_id' => 'client-id-2',
                'client_secret' => 'client-secret-2',
                'user_id' => '',
                'refresh_token' => $refresh_token
            ],
            [
                'grant_type' => 'refresh_token',
                'client_id' => 'client-id-1',
                'client_secret' => 'client-secret-1',
                'user_id' => '',
                'refresh_token' => $refresh_token
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'token',
                [
                    $param['grant_type'],
                    $param['client_id'],
                    $param['client_secret'],
                    $param['user_id'],
                    $param['refresh_token']
                ]
            );

            if (in_array($i, [0, 1, 3])) {
                $this->assertEquals(400, @$response['code']);
                $this->assertEquals('error', @$response['status']);
            }

            if (in_array($i, [0]))
                $this->assertEquals('invalid_grant_type', @$response['type']);
            if (in_array($i, [1]))
                $this->assertEquals('invalid_client_credentials', @$response['type']);
            if (in_array($i, [2])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('access_token', @$response['data']);
                $this->assertArrayHasKey('expires_in',   @$response['data']);
                $this->assertArrayHasKey('token_type',   @$response['data']);

                self::$AccessTokensStorage->deleteAccessToken(@$response['data']['access_token']);
            }
            if (in_array($i, [3]))
                $this->assertEquals('user_id_required', @$response['type']);
            if (in_array($i, [4])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('refresh_token', @$response['data']);
                $this->assertArrayHasKey('access_token',  @$response['data']);
                $this->assertArrayHasKey('expires_in',    @$response['data']);
                $this->assertArrayHasKey('token_type',    @$response['data']);

                self::$AccessTokensStorage->deleteAccessToken(@$response['data']['access_token']);
                self::$RefreshTokensStorage->deleteRefreshToken(@$response['data']['refresh_token']);
            }
            if (in_array($i, [5])) {
                $this->assertEquals(400, @$response['code']);
                $this->assertEquals('error', @$response['status']);
                $this->assertEquals('invalid_for_client', @$response['type']);
            }
            if (in_array($i, [6])) {
                $this->assertEquals(200, @$response['code']);
                $this->assertEquals('success', @$response['status']);
                $this->assertIsArray(@$response['data']);
                $this->assertNotEmpty(@$response['data']);
                $this->assertArrayHasKey('refresh_token', @$response['data']);
                $this->assertArrayHasKey('access_token',  @$response['data']);
                $this->assertArrayHasKey('expires_in',    @$response['data']);
                $this->assertArrayHasKey('token_type',    @$response['data']);

                self::$AccessTokensStorage->deleteAccessToken(@$response['data']['access_token']);
                self::$RefreshTokensStorage->deleteRefreshToken(@$response['data']['refresh_token']);
            }
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\OAuth2::revoke
     * 
     * @return void
     */
    public function revoke()
    {
        // Create valid access token
        $access_token = generateUniqueId(self::$config['access_token_length']);
        self::$AccessTokensStorage->insertAccessToken(
            $access_token,
            'client-id-3',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('+1 Hour'))
        );

        // Create valid refresh token
        $refresh_token = generateUniqueId(self::$config['refresh_token_length']);
        self::$RefreshTokensStorage->insertRefreshToken(
            $refresh_token,
            'client-id-3',
            generateUniqueId(32),
            date('Y-m-d H:i:s', strtotime('+1 Day'))
        );

        $test = [
            [
                'access_token' => $access_token,
                'refresh_token' => $refresh_token,
            ]
        ];

        foreach ($test as $i => $param) {
            $response = invokeMethod(
                self::$OAuth2,
                'revoke',
                [$param['access_token'], $param['refresh_token']]
            );
            $this->assertEquals(200, @$response['code']);
            $this->assertEquals('success', @$response['status']);

            $access = self::$AccessTokensStorage->getAccessToken(trim($param['access_token']));
            $this->assertEmpty($access);

            $refresh = self::$RefreshTokensStorage->getRefreshToken(trim($param['refresh_token']));
            $this->assertEmpty($refresh);
        }
    }
}
