<?php

namespace FRUnitTest\OAuth2\Storage\Oracle;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\Oracle\RefreshTokensStorage;

class RefreshTokensStorageTest extends TestCase
{
    protected static $OracleTestAsset;
    protected static $DB;
    protected static $refresh_token_table_name;
    protected static $refresh_token_length;
    protected static $RefreshTokensStorage;

    /**
     * This method is executed only once per class
     *
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        self::$OracleTestAsset = new OracleTestAsset();

        self::$DB = self::$OracleTestAsset->getDB();
        self::$refresh_token_table_name = self::$OracleTestAsset->getRefreshTokenTableName();
        self::$refresh_token_length = self::$OracleTestAsset->getRefreshTokenLength();
        self::$RefreshTokensStorage = self::$OracleTestAsset->getRefreshTokensStorage();
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::__construct
     * 
     * @return void
     */
    public function constructor()
    {
        $invalid_refresh_token_table_name = ['', 123, true, []];
        foreach ($invalid_refresh_token_table_name as $i => $refresh_token_table_name) {
            $exception = false;
            try {
                new RefreshTokensStorage(self::$DB, $refresh_token_table_name, self::$refresh_token_length);
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `refresh_token_table_name` cannot be empty and must be string');
        }

        $invalid_refresh_token_length = ['32', true, 16, 39];
        foreach ($invalid_refresh_token_length as $i => $refresh_token_length) {
            $exception = false;
            try {
                new RefreshTokensStorage(self::$DB, self::$refresh_token_table_name, $refresh_token_length);
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `refresh_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8');
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::createDBStructure
     * 
     * @return void
     */
    public function createDBStructure()
    {
        self::$RefreshTokensStorage->createDBStructure();

        $query = ' SELECT UPPER(TABLE_NAME) TABLE_NAME FROM ALL_TABLES 
                    WHERE UPPER(OWNER || \'.\' || TABLE_NAME)
                                IN (:refresh_token_table_name)  ';
        $values = [
            ':refresh_token_table_name' => str_replace('"', '', strtoupper(self::$refresh_token_table_name)),
        ];
        $rows = self::$DB->fetchRows($query, $values);
        $this->assertNotEmpty($rows);
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::insertRefreshToken
     * 
     * @return array
     */
    public function insertRefreshToken()
    {
        $test = [
            [
                'refresh_token' => generateUniqueId(self::$refresh_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('+ 1 Hour')),
            ],
            [
                'refresh_token' => generateUniqueId(self::$refresh_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('- 1 Second')),
            ],
            [
                'refresh_token' => generateUniqueId(self::$refresh_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('- 1 Minute')),
            ],
        ];
        $inserted = [];

        foreach ($test as $i => $param) {
            // Insert into database
            invokeMethod(
                self::$RefreshTokensStorage,
                'insertRefreshToken',
                [
                    $param['refresh_token'],
                    $param['client_id'],
                    $param['user_id'],
                    $param['expired_at']
                ]
            );
            $this->assertTrue(true);

            $inserted[] = $param;
        }

        return $inserted;
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::getRefreshToken
     * @depends insertRefreshToken
     * 
     * @return void
     */
    public function getRefreshToken($test)
    {
        foreach ($test as $i => $param) {
            $row = invokeMethod(
                self::$RefreshTokensStorage,
                'getRefreshToken',
                [
                    $param['refresh_token'],
                ]
            );

            $this->assertArrayHasKey('refresh_token', $row);
            $this->assertArrayHasKey('client_id', $row);
            $this->assertArrayHasKey('user_id', $row);
            $this->assertArrayHasKey('expired_at', $row);

            $this->assertEqualsIgnoringCase($param['refresh_token'], $row['refresh_token']);
            $this->assertEquals($param['client_id'], $row['client_id']);
            $this->assertEqualsIgnoringCase($param['user_id'], $row['user_id']);
            $this->assertEquals($param['expired_at'], $row['expired_at']);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::deleteRefreshToken
     * @depends insertRefreshToken
     * 
     * @return void
     */
    public function deleteRefreshToken($test)
    {
        foreach ($test as $i => $param) {
            invokeMethod(
                self::$RefreshTokensStorage,
                'deleteRefreshToken',
                [
                    $param['refresh_token'],
                ]
            );

            $row = invokeMethod(
                self::$RefreshTokensStorage,
                'getRefreshToken',
                [
                    $param['refresh_token'],
                ]
            );

            $this->assertIsArray($row);
            $this->assertEmpty($row);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::getExpiredRefreshTokens
     * 
     * @return void
     */
    public function getExpiredRefreshTokens()
    {
        // Create expired refresh token
        invokeMethod(
            self::$RefreshTokensStorage,
            'insertRefreshToken',
            [
                generateUniqueId(self::$refresh_token_length),
                'client-id',
                generateUniqueId(32),
                date('Y-m-d H:i:s', strtotime('-1 Second'))
            ]
        );

        // Test
        $rows = invokeMethod(
            self::$RefreshTokensStorage,
            'getExpiredRefreshTokens',
            []
        );
        $this->assertIsArray($rows);
        $this->assertNotEmpty($rows);
        $row = $rows[0];

        $this->assertArrayHasKey('refresh_token', $row);
        $this->assertArrayHasKey('client_id', $row);
        $this->assertArrayHasKey('user_id', $row);
        $this->assertArrayHasKey('expired_at', $row);
        // Refresh token must be expired
        $this->assertTrue((time() > strtotime($row['expired_at'])));
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Oracle\RefreshTokensStorage::deleteExpiredRefreshTokens
     * 
     * @return void
     */
    public function deleteExpiredRefreshTokens()
    {
        invokeMethod(
            self::$RefreshTokensStorage,
            'deleteExpiredRefreshTokens',
            []
        );

        $rows = invokeMethod(
            self::$RefreshTokensStorage,
            'getExpiredRefreshTokens',
            []
        );

        $this->assertIsArray($rows);
        $this->assertEmpty($rows);
    }
}
