<?php

namespace FRUnitTest\OAuth2;

use PHPUnit\Framework\TestCase;
use FRUnitTest\OAuth2\Storage\Memory\MemoryTestAsset;
use FRUnitTest\OAuth2\Storage\Oracle\OracleTestAsset;
use FRUnitTest\OAuth2\Storage\MySQL\MySQLTestAsset;
use FR\ServiceResponse\ServiceResponse;
use FR\OAuth2\OAuth2;

class OAuth2TestAsset extends TestCase
{
    public function getServiceResponse()
    {
        $ServiceResponse = new ServiceResponse();
        return $ServiceResponse;
    }

    public function getConfig()
    {
        $config = [
            // 1 Hour
            'access_token_lifetime'          => 3600,
            // Length of access_token
            'access_token_length'            => 64,
            // 14 Days  
            'refresh_token_lifetime'         => 1209600,
            // Length of refresh_token 
            'refresh_token_length'           => 64,
            // Token type 
            'token_type'                     => 'Bearer',
            // Create new refresh token once used
            'always_issue_new_refresh_token' => true,
            // Valid grant types
            'grant_types'                    =>  [
                'client_credentials',
                'password',
                'refresh_token'
            ]
        ];

        return $config;
    }

    public function getClientsStorage()
    {
        $StorageTestAsset = new MemoryTestAsset();
        return $StorageTestAsset->getClientsStorage();
    }

    public function getAccessTokensStorage()
    {
        if (TEST_FR_OAUTH2_ACCESS_TOKENS_STORAGE == 'Oracle') {
            if (!TEST_FR_OAUTH2_STORAGE_ORACLE)
                throw new \Exception('TEST_FR_OAUTH2_STORAGE_ORACLE is not enabled in phpunit.xml');

            $StorageTestAsset =  new OracleTestAsset();
        } else if (TEST_FR_OAUTH2_ACCESS_TOKENS_STORAGE == 'MySQL') {
            if (!TEST_FR_OAUTH2_STORAGE_MYSQL)
                throw new \Exception('TEST_FR_OAUTH2_STORAGE_MYSQL is not enabled in phpunit.xml');

            $StorageTestAsset =  new MySQLTestAsset();
        } else {
            throw new \Exception('Invalid value for TEST_FR_OAUTH2_ACCESS_TOKENS_STORAGE in phpunit.xml');
        }

        return $StorageTestAsset->getAccessTokensStorage();
    }

    public function getRefreshTokensStorage()
    {
        if (TEST_FR_OAUTH2_REFRESH_TOKENS_STORAGE == 'Oracle') {
            if (!TEST_FR_OAUTH2_STORAGE_ORACLE)
                throw new \Exception('TEST_FR_OAUTH2_STORAGE_ORACLE is not enabled in phpunit.xml');

            $StorageTestAsset =  new OracleTestAsset();
        } else if (TEST_FR_OAUTH2_REFRESH_TOKENS_STORAGE == 'MySQL') {
            if (!TEST_FR_OAUTH2_STORAGE_MYSQL)
                throw new \Exception('TEST_FR_OAUTH2_STORAGE_MYSQL is not enabled in phpunit.xml');

            $StorageTestAsset =  new MySQLTestAsset();
        } else {
            throw new \Exception('Invalid value for TEST_FR_OAUTH2_REFRESH_TOKENS_STORAGE in phpunit.xml');
        }

        return $StorageTestAsset->getRefreshTokensStorage();
    }

    public function getOAuth2()
    {
        $OAuth2 = new OAuth2(
            $this->getServiceResponse(),
            $this->getConfig(),
            $this->getClientsStorage(),
            $this->getAccessTokensStorage(),
            $this->getRefreshTokensStorage()
        );

        return $OAuth2;
    }
}
