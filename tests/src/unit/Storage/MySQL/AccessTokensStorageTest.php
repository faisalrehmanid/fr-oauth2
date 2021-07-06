<?php

namespace FRUnitTest\OAuth2\Storage\MySQL;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\MySQL\AccessTokensStorage;

class AccessTokensStorageTest extends TestCase
{
    protected static $MySQLTestAsset;
    protected static $DB;
    protected static $access_token_table_name;
    protected static $access_token_length;
    protected static $AccessTokensStorage;

    /**
     * This method is executed only once per class
     *
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        self::$MySQLTestAsset = new MySQLTestAsset();

        self::$DB = self::$MySQLTestAsset->getDB();
        self::$access_token_table_name = self::$MySQLTestAsset->getAccessTokenTableName();
        self::$access_token_length = self::$MySQLTestAsset->getAccessTokenLength();
        self::$AccessTokensStorage = self::$MySQLTestAsset->getAccessTokensStorage();
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::__construct
     * 
     * @return void
     */
    public function constructor()
    {
        $invalid_access_token_table_name = ['', 123, true, []];
        foreach ($invalid_access_token_table_name as $i => $access_token_table_name) {
            $exception = false;
            try {
                new AccessTokensStorage(self::$DB, $access_token_table_name, self::$access_token_length);
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `access_token_table_name` cannot be empty and must be string');
        }

        $invalid_access_token_length = ['32', true, 16, 39];
        foreach ($invalid_access_token_length as $i => $access_token_length) {
            $exception = false;
            try {
                new AccessTokensStorage(self::$DB, self::$access_token_table_name, $access_token_length);
            } catch (\Exception $expected) {
                $exception = true;
            }
            $this->assertTrue($exception, 'Exception not thrown: `access_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8');
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::createDBStructure
     * 
     * @return void
     */
    public function createDBStructure()
    {
        self::$AccessTokensStorage->createDBStructure();

        $query = ' SELECT table_name FROM information_schema.tables 
                        WHERE LOWER(CONCAT(table_schema, \'.\' ,table_name)) 
                        IN (:access_token_table_name)';
        $values = [
            ':access_token_table_name' => str_replace('`', '', strtolower(self::$access_token_table_name)),
        ];
        $rows = self::$DB->fetchRows($query, $values);
        $this->assertNotEmpty($rows);
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::insertAccessToken
     * 
     * @return array
     */
    public function insertAccessToken()
    {
        $test = [
            [
                'access_token' => generateUniqueId(self::$access_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('+ 1 Hour')),
            ],
            [
                'access_token' => generateUniqueId(self::$access_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('- 1 Second')),
            ],
            [
                'access_token' => generateUniqueId(self::$access_token_length),
                'client_id' => 'client-id',
                'user_id' => generateUniqueId(32),
                'expired_at' => date('Y-m-d H:i:s', strtotime('- 1 Minute')),
            ],
        ];
        $inserted = [];

        foreach ($test as $i => $param) {
            // Insert into database
            invokeMethod(
                self::$AccessTokensStorage,
                'insertAccessToken',
                [
                    $param['access_token'],
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
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::getAccessToken
     * @depends insertAccessToken
     * 
     * @return void
     */
    public function getAccessToken($test)
    {
        foreach ($test as $i => $param) {
            $row = invokeMethod(
                self::$AccessTokensStorage,
                'getAccessToken',
                [
                    $param['access_token'],
                ]
            );

            $this->assertArrayHasKey('access_token', $row);
            $this->assertArrayHasKey('client_id', $row);
            $this->assertArrayHasKey('user_id', $row);
            $this->assertArrayHasKey('expired_at', $row);

            $this->assertEqualsIgnoringCase($param['access_token'], $row['access_token']);
            $this->assertEquals($param['client_id'], $row['client_id']);
            $this->assertEqualsIgnoringCase($param['user_id'], $row['user_id']);
            $this->assertEquals($param['expired_at'], $row['expired_at']);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::deleteAccessToken
     * @depends insertAccessToken
     * 
     * @return void
     */
    public function deleteAccessToken($test)
    {
        foreach ($test as $i => $param) {
            invokeMethod(
                self::$AccessTokensStorage,
                'deleteAccessToken',
                [
                    $param['access_token'],
                ]
            );

            $row = invokeMethod(
                self::$AccessTokensStorage,
                'getAccessToken',
                [
                    $param['access_token'],
                ]
            );

            $this->assertIsArray($row);
            $this->assertEmpty($row);
        }
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::getExpiredAccessTokens
     * 
     * @return void
     */
    public function getExpiredAccessTokens()
    {
        // Create expired access token
        invokeMethod(
            self::$AccessTokensStorage,
            'insertAccessToken',
            [
                generateUniqueId(self::$access_token_length),
                'client-id',
                generateUniqueId(32),
                date('Y-m-d H:i:s', strtotime('-1 Second'))
            ]
        );

        // Test
        $rows = invokeMethod(
            self::$AccessTokensStorage,
            'getExpiredAccessTokens',
            []
        );
        $this->assertIsArray($rows);
        $this->assertNotEmpty($rows);
        $row = $rows[0];

        $this->assertArrayHasKey('access_token', $row);
        $this->assertArrayHasKey('client_id', $row);
        $this->assertArrayHasKey('user_id', $row);
        $this->assertArrayHasKey('expired_at', $row);
        // Access token must be expired
        $this->assertTrue((time() > strtotime($row['expired_at'])));
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\MySQL\AccessTokensStorage::deleteExpiredAccessTokens
     * 
     * @return void
     */
    public function deleteExpiredAccessTokens()
    {
        invokeMethod(
            self::$AccessTokensStorage,
            'deleteExpiredAccessTokens',
            []
        );

        $rows = invokeMethod(
            self::$AccessTokensStorage,
            'getExpiredAccessTokens',
            []
        );

        $this->assertIsArray($rows);
        $this->assertEmpty($rows);
    }
}
