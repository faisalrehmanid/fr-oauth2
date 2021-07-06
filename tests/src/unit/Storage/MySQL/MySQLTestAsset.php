<?php

namespace FRUnitTest\OAuth2\Storage\MySQL;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\MySQL\AccessTokensStorage;
use FR\OAuth2\Storage\MySQL\RefreshTokensStorage;
use FR\Db\DbFactory;

class MySQLTestAsset extends TestCase
{
    public function getDB()
    {
        // Skip this test if disabled
        if (!TEST_FR_OAUTH2_STORAGE_MYSQL)
            $this->markTestSkipped('TEST_FR_OAUTH2_STORAGE_MYSQL is disabled in phpunit.xml');

        // MySQL connection configuration
        $config =  array(
            'driver'    => 'TEST_FR_OAUTH2_STORAGE_MYSQL_DRIVER',
            'hostname'  => 'TEST_FR_OAUTH2_STORAGE_MYSQL_HOSTNAME',
            'port'      => 'TEST_FR_OAUTH2_STORAGE_MYSQL_PORT',
            'username'  => 'TEST_FR_OAUTH2_STORAGE_MYSQL_USERNAME',
            'password'  => 'TEST_FR_OAUTH2_STORAGE_MYSQL_PASSWORD',
            'database'  => 'TEST_FR_OAUTH2_STORAGE_MYSQL_DATABASE',
            'charset'   => 'TEST_FR_OAUTH2_STORAGE_MYSQL_CHARSET',
        );

        // Validate connection configurations
        foreach ($config as $key => $value) {
            if (!defined($value)) {
                throw new \Exception('const ' . $value . ' not defined in phpunit.xml');
            }

            if (empty(constant($value)) && !in_array($key, ['password'])) {
                throw new \Exception('value required for const ' . $value . ' in phpunit.xml');
            }

            // Assign constant value in $config
            $config[$key] = constant($value);
        }

        // Create $db object and connect to database
        $DB = new DbFactory();
        $DB = $DB->init($config);
        return $DB;
    }

    public function getAccessTokenLength()
    {
        return 64;
    }

    public function getAccessTokenTableName()
    {
        return strtolower(TEST_FR_OAUTH2_STORAGE_MYSQL_ACCESS_TOKEN_TABLE_NAME);
    }

    public function getAccessTokensStorage()
    {
        return new AccessTokensStorage(
            $this->getDB(),
            $this->getAccessTokenTableName(),
            $this->getAccessTokenLength()
        );
    }

    public function getRefreshTokenLength()
    {
        return 64;
    }

    public function getRefreshTokenTableName()
    {
        return strtolower(TEST_FR_OAUTH2_STORAGE_MYSQL_REFRESH_TOKEN_TABLE_NAME);
    }

    public function getRefreshTokensStorage()
    {
        return new RefreshTokensStorage(
            $this->getDB(),
            $this->getRefreshTokenTableName(),
            $this->getRefreshTokenLength()
        );
    }
}
