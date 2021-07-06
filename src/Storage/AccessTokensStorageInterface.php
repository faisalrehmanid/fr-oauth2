<?php

namespace FR\OAuth2\Storage;

interface AccessTokensStorageInterface
{
    /**
     * Get access token details
     * access_token is case insensitive
     *
     * @param string $access_token
     * @return array
     */
    public function getAccessToken($access_token);

    /**
     * Get all expired access tokens
     *
     * @return array
     */
    public function getExpiredAccessTokens();

    /**
     * Insert access token details
     *
     * @param string $access_token
     * @param string $client_id 
     * @param string $user_id
     * @param string $expired_at Datetime format: Y-m-d H:i:s
     * @return void
     */
    public function insertAccessToken(
        $access_token,
        $client_id,
        $user_id,
        $expired_at
    );

    /**
     * Delete access token details
     *
     * @param string $access_token
     * @return void
     */
    public function deleteAccessToken($access_token);

    /**
     * Delete all expired access tokens
     *
     * @return void
     */
    public function deleteExpiredAccessTokens();
}
