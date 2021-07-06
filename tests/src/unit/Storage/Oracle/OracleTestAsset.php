<?php

namespace FRUnitTest\OAuth2\Storage\Oracle;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\Oracle\AccessTokensStorage;
use FR\OAuth2\Storage\Oracle\RefreshTokensStorage;
use FR\Db\DbFactory;

class OracleTestAsset extends TestCase
{
    public function getDB()
    {
        // Skip this test if disabled
        if (!TEST_FR_OAUTH2_STORAGE_ORACLE)
            $this->markTestSkipped('TEST_FR_OAUTH2_STORAGE_ORACLE is disabled in phpunit.xml');

        // Oracle connection configuration
        $config =  array(
            'driver'        => 'TEST_FR_OAUTH2_STORAGE_ORACLE_DRIVER',
            'connection'    => 'TEST_FR_OAUTH2_STORAGE_ORACLE_CONNECTION',
            'username'      => 'TEST_FR_OAUTH2_STORAGE_ORACLE_USERNAME',
            'password'      => 'TEST_FR_OAUTH2_STORAGE_ORACLE_PASSWORD',
            'character_set' => 'TEST_FR_OAUTH2_STORAGE_ORACLE_CHARACTER_SET'
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
        return strtoupper(TEST_FR_OAUTH2_STORAGE_ORACLE_ACCESS_TOKEN_TABLE_NAME);
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
        return strtoupper(TEST_FR_OAUTH2_STORAGE_ORACLE_REFRESH_TOKEN_TABLE_NAME);
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
