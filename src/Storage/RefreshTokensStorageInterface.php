<?php

namespace FR\OAuth2\Storage;

interface RefreshTokensStorageInterface
{
    /**
     * Get refresh token details
     * refresh_token is case insensitive
     *
     * @param string $refresh_token
     * @return array
     */
    public function getRefreshToken($refresh_token);

    /**
     * Get all expired refresh tokens
     *
     * @return array
     */
    public function getExpiredRefreshTokens();

    /**
     * Insert refresh token details
     *
     * @param string $refresh_token
     * @param string $client_id 
     * @param string $user_id
     * @param string $expired_at Datetime format: Y-m-d H:i:s
     * @return void
     */
    public function insertRefreshToken(
        $refresh_token,
        $client_id,
        $user_id,
        $expired_at
    );

    /**
     * Delete refresh token details
     *
     * @param string $refresh_token
     * @return void
     */
    public function deleteRefreshToken($refresh_token);

    /**
     * Delete all expired refresh tokens
     *
     * @return void
     */
    public function deleteExpiredRefreshTokens();
}
