<?php

namespace FR\OAuth2;

use FR\ServiceResponse\ServiceResponseInterface;

/**
 * @author Faisal Rehman <faisalrehmanid@hotmail.com>
 * 
 * This class provide OAuth2 implementation
 * 
 * Example: How to use this class?
 * 
 * ```
 * <?php
 *      // Provide constructor parameters accordingly
 *      $OAuth2 = new \FR\OAuth2\OAuth2();
 * 
 *      // Verify given access token
 *      $ServiceResponse = $OAuth2->verifyAccessToken($token_type, $access_token); 
 * 
 *      // Get access and refresh token according to the given grant type
 *      $ServiceResponse = $OAuth2->token(  $grant_type,
 *                                          $client_id,
 *                                          $client_secret,
 *                                          $user_id,
 *                                          $refresh_token);
 * 
 *      // Remove access and refresh token
 *      $ServiceResponse = $OAuth2->revoke($access_token, $refresh_token);
 * 
 *      // Remove all expired access and refresh tokens
 *      $ServiceResponse = $OAuth2->deleteExpiredTokens();
 * ?>
 * ```
 */
class OAuth2
{
    protected $ServiceResponse;
    protected $config;
    protected $ClientsStorage;
    protected $AccessTokensStorage;
    protected $RefreshTokensStorage;

    /**
     * Create OAuth2 object
     *
     * @param object \FR\ServiceResponse\ServiceResponseInterface $ServiceResponse
     * @param array $config = [  // 1 Hour
     *                           'access_token_lifetime'          => 3600,
     *                           // Length of access_token
     *                           'access_token_length'            => 64,
     *                           // 14 Days  
     *                           'refresh_token_lifetime'         => 1209600,
     *                           // Length of refresh_token 
     *                           'refresh_token_length'           => 64,
     *                           // Token type 
     *                           'token_type'                     => 'Bearer',
     *                           // Create new refresh token once used
     *                           'always_issue_new_refresh_token' => true,
     *                           // Valid grant types
     *                           'grant_types'                    =>  ['client_credentials',
     *                                                                 'password',
     *                                                                 'refresh_token'
     *                            ]
     *                          ];
     *  
     * @param object Storage\ClientsStorageInterface $ClientsStorage
     * @param object Storage\AccessTokensStorageInterface $AccessTokensStorage
     * @param object Storage\RefreshTokensStorageInterface $RefreshTokensStorage
     */
    public function __construct(
        ServiceResponseInterface $ServiceResponse,
        array $config,
        Storage\ClientsStorageInterface $ClientsStorage,
        Storage\AccessTokensStorageInterface $AccessTokensStorage,
        Storage\RefreshTokensStorageInterface $RefreshTokensStorage
    ) {
        @$access_token_lifetime = $config['access_token_lifetime'];
        @$access_token_length = $config['access_token_length'];
        @$refresh_token_lifetime = $config['refresh_token_lifetime'];
        @$refresh_token_length = $config['refresh_token_length'];
        @$token_type = trim($config['token_type']);
        @$always_issue_new_refresh_token = $config['always_issue_new_refresh_token'];
        @$grant_types = $config['grant_types'];

        if (
            !$access_token_lifetime ||
            !is_int($access_token_lifetime) ||
            @$access_token_lifetime < 60
        )
            throw new \Exception('`access_token_lifetime` cannot be empty and must be integer and must be greater than or equal to 60 seconds');

        if (
            !$access_token_length ||
            !is_int($access_token_length) ||
            $access_token_length < 32 ||
            $access_token_length > 128 ||
            !(($access_token_length % 8) == 0)
        )
            throw new \Exception('`access_token_length` cannot be empty and must be integer and must be from 32 to 128 chars and must be divisible by 8');


        if (
            !$refresh_token_lifetime ||
            !is_int($refresh_token_lifetime) ||
            @$refresh_token_lifetime < 60
        )
            throw new \Exception('`refresh_token_lifetime` cannot be empty and must be integer and must be greater than or equal to 60 seconds');

        if (
            !$refresh_token_length ||
            !is_int($refresh_token_length) ||
            $refresh_token_length < 32 ||
            $refresh_token_length > 128 ||
            !(($refresh_token_length % 8) == 0)
        )
            throw new \Exception('`refresh_token_length` cannot be empty and must be integer and must be from 32 to 128 chars and must be divisible by 8');

        $token_types = ['Bearer'];
        if (
            !$token_type ||
            !is_string($token_type) ||
            !in_array($token_type, $token_types)
        )
            throw new \Exception('`token_type` cannot be empty and must be in ' . implode(", ", $token_types));

        if (!is_bool($always_issue_new_refresh_token))
            throw new \Exception('`always_issue_new_refresh_token` must be boolean');

        // Supported grant types
        $supported_grant_types = ['client_credentials', 'password', 'refresh_token'];
        foreach ($grant_types as $grant_type) {
            if (!in_array($grant_type, $supported_grant_types))
                throw new \Exception('`grant_types` must be from ' . implode(', ', $supported_grant_types));
        }

        $this->ServiceResponse = $ServiceResponse;
        $this->config = $config;
        $this->ClientsStorage = $ClientsStorage;
        $this->AccessTokensStorage = $AccessTokensStorage;
        $this->RefreshTokensStorage = $RefreshTokensStorage;
    }

    /**
     * Generate Unique ID of fixed length
     *
     * @param int $length
     * @return string
     */
    protected function generateUniqueId($length)
    {
        $length = intval($length) / 2;

        if (function_exists('random_bytes')) {
            $random = random_bytes($length);
        }

        if (function_exists('openssl_random_pseudo_bytes')) {
            $random = openssl_random_pseudo_bytes($length);
        }

        if ($random !== false && strlen($random) === $length) {
            return  bin2hex($random);
        }

        $unique_id = '';
        $characters = '0123456789abcdef';
        for ($i = 0; $i < ($length * 2); $i++) {
            $unique_id .= $characters[rand(0, strlen($characters) - 1)];
        }

        return $unique_id;
    }

    /**
     * Verify client credentials
     *
     * @param string $client_id Case insensitive
     * @param string $client_secret Case insensitive
     * @return array of ServiceResponse
     */
    protected function verifyClientCredentials($client_id, $client_secret)
    {
        $client_id = trim($client_id);
        $client_secret = trim($client_secret);

        $client = $this->ClientsStorage->getClientById($client_id);

        if (empty($client))
            return $this->ServiceResponse->error(400, 'client_not_found', 'Client not found')->toArray();

        if (strtolower($client['client_secret']) != strtolower($client_secret))
            return $this->ServiceResponse->error(400, 'invalid_client_credentials', 'Invalid client credentials')->toArray();

        unset($client['client_secret']);
        return $this->ServiceResponse->success(200, $client)->toArray();
    }

    /**
     * Create access token
     *
     * @param string $client_id Case insensitive
     * @param string $user_id Case insensitive
     * @return array of ServiceResponse
     */
    protected function createAccessToken($client_id, $user_id = '')
    {
        $client_id = trim($client_id);
        $user_id = trim($user_id);

        $access_token = $this->generateUniqueId($this->config['access_token_length']);
        $expired_at = date('Y-m-d H:i:s', time() + $this->config['access_token_lifetime']);
        $this->AccessTokensStorage->insertAccessToken(
            $access_token,
            $client_id,
            $user_id,
            $expired_at
        );

        $data = [
            'access_token' => $access_token,
            'expires_in'   => $this->config['access_token_lifetime'],
            'token_type'   => $this->config['token_type'],
        ];

        return $this->ServiceResponse->success(200, $data)->toArray();
    }

    /**
     * Create refresh token
     *
     * @param string $client_id Case insensitive
     * @param string $user_id Case insensitive
     * @return array of ServiceResponse
     */
    protected function createRefreshToken($client_id, $user_id)
    {
        $client_id = trim($client_id);
        $user_id = trim($user_id);

        $refresh_token = $this->generateUniqueId($this->config['refresh_token_length']);
        $expired_at = date('Y-m-d H:i:s', time() + $this->config['refresh_token_lifetime']);
        $this->RefreshTokensStorage->insertRefreshToken(
            $refresh_token,
            $client_id,
            $user_id,
            $expired_at
        );

        $data = [
            'refresh_token' => $refresh_token,
        ];

        return $this->ServiceResponse->success(200, $data)->toArray();
    }

    /**
     * Verify refresh token
     *
     * @param string $client_id Case insensitive
     * @param string $refresh_token Case insensitive
     * @return array of ServiceResponse
     */
    protected function verifyRefreshToken($client_id, $refresh_token)
    {
        $client_id = trim($client_id);
        $refresh_token = trim($refresh_token);

        if (
            !$client_id ||
            !$refresh_token
        )
            return $this->ServiceResponse->error(400, 'client_id_refresh_token_required', 'client_id and refresh_token required')->toArray();


        $refresh = $this->RefreshTokensStorage->getRefreshToken($refresh_token);
        if (
            empty($refresh)
            || empty($refresh['refresh_token'])
            || empty($refresh['client_id'])
            || empty($refresh['expired_at'])
        )
            return $this->ServiceResponse->error(400, 'invalid_refresh_token', 'invalid refresh_token')->toArray();

        if (strtolower($refresh['client_id']) != strtolower($client_id))
            return $this->ServiceResponse->error(400, 'invalid_for_client', 'refresh_token is invalid for client')->toArray();

        if (time() > strtotime($refresh['expired_at']))
            return $this->ServiceResponse->error(400, 'expired_refresh_token', 'Refresh token has expired')->toArray();

        return $this->ServiceResponse->success(200, $refresh)->toArray();
    }

    /**
     * Verify access token
     *
     * @param string $token_type Case sensitive
     * @param string $access_token Case insensitive
     * @return array of ServiceResponse
     */
    public function verifyAccessToken($token_type, $access_token)
    {
        $token_type = trim($token_type);
        $access_token = trim($access_token);

        if (!$token_type || !$access_token)
            return $this->ServiceResponse->error(403, 'token_type_access_token_required', 'access_token with token_type required')->toArray();

        if ($token_type != $this->config['token_type'])
            return $this->ServiceResponse->error(403, 'invalid_token_type', 'Invalid token_type')->toArray();

        $access = $this->AccessTokensStorage->getAccessToken($access_token);
        if (
            empty($access)
            || empty($access['access_token'])
            || empty($access['client_id'])
            || empty($access['expired_at'])
        )
            return $this->ServiceResponse->error(403, 'invalid_access_token', 'Invalid access_token')->toArray();

        if (time() > strtotime($access['expired_at']))
            return $this->ServiceResponse->error(401, 'expired_access_token', 'Access token has expired')->toArray();

        return $this->ServiceResponse->success(200, $access)->toArray();
    }

    /**
     * Token
     *
     * @param string $grant_type 
     * @param string $client_id Case insensitive
     * @param string $client_secret Case insensitive
     * @param string $user_id Case insensitive
     * @param string $refresh_token Case insensitive
     * @return array of ServiceResponse
     */
    public function token(
        $grant_type,
        $client_id,
        $client_secret,
        $user_id,
        $refresh_token
    ) {
        $grant_type = trim($grant_type);
        $client_id = trim($client_id);
        $client_secret = trim($client_secret);
        $user_id = trim($user_id);
        $refresh_token = trim($refresh_token);

        if (!in_array($grant_type, $this->config['grant_types']))
            return $this->ServiceResponse->error(400, 'invalid_grant_type', 'grant_type must be one of ' . implode(', ', $this->config['grant_types']))->toArray();

        // Verify client credentials for all grant types
        $response = $this->verifyClientCredentials($client_id, $client_secret);
        if ($response['status'] != 'success') return $response;
        @$client_id = $response['data']['client_id'];

        if ($grant_type == 'client_credentials') {
            return $this->createAccessToken($client_id);
        }

        if ($grant_type == 'password') {
            if (!$user_id)
                return $this->ServiceResponse->error(400, 'user_id_required', 'user_id required')->toArray();

            $response = $this->createRefreshToken($client_id, $user_id);
            if ($response['status'] != 'success') return $response;
            $refresh = $response['data'];

            $response = $this->createAccessToken($client_id, $user_id);
            if ($response['status'] != 'success') return $response;
            $access = $response['data'];
            $access['refresh_token'] = $refresh['refresh_token'];

            return $this->ServiceResponse->success(200, $access)->toArray();
        }

        if ($grant_type == 'refresh_token') {
            $response = $this->verifyRefreshToken($client_id, $refresh_token);
            if ($response['status'] != 'success') return $response;
            $refresh = $response['data'];

            $response = $this->createAccessToken($refresh['client_id'], $refresh['user_id']);
            if ($response['status'] != 'success') return $response;
            $access = $response['data'];
            $access['refresh_token'] = $refresh_token;

            if ($this->config['always_issue_new_refresh_token']) {
                $this->RefreshTokensStorage->deleteRefreshToken($refresh_token);

                $response = $this->createRefreshToken($refresh['client_id'], $refresh['user_id']);
                if ($response['status'] != 'success') return $response;
                $refresh = $response['data'];

                $access['refresh_token'] = $refresh['refresh_token'];
            }

            return $this->ServiceResponse->success(200, $access)->toArray();
        }
    }

    /**
     * Revoke access token and refresh token
     *
     * @param string $access_token Optional and case insensitive
     * @param string $refresh_token Optional and case insensitive
     * @return array of ServiceResponse
     */
    public function revoke($access_token = '', $refresh_token = '')
    {
        $access_token  = trim($access_token);
        $refresh_token = trim($refresh_token);

        if ($access_token)
            $this->AccessTokensStorage->deleteAccessToken($access_token);

        if ($refresh_token)
            $this->RefreshTokensStorage->deleteRefreshToken($refresh_token);

        return $this->ServiceResponse->success(200)->toArray();
    }

    /**
     * Remove all expired access and refresh tokens
     *
     * @return array of ServiceResponse
     */
    public function deleteExpiredTokens()
    {
        $this->AccessTokensStorage->deleteExpiredAccessTokens();
        $this->RefreshTokensStorage->deleteExpiredRefreshTokens();

        return $this->ServiceResponse->success(200)->toArray();
    }
}
