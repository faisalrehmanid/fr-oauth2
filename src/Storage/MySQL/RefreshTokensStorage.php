<?php

namespace FR\OAuth2\Storage\MySQL;

use FR\Db\DbInterface;
use FR\OAuth2\Storage\RefreshTokensStorageInterface;

class RefreshTokensStorage implements RefreshTokensStorageInterface
{
    /**
     * @var object FR\Db\DbInterface
     */
    protected $DB;

    /**
     * Refresh token table name Like: schema.table_name
     *
     * @var string
     */
    protected $refresh_token_table_name;

    /**
     * Refresh token length
     *
     * @var int
     */
    protected $refresh_token_length;

    /**
     * Refresh token storage
     *
     * @param object FR\Db\DbInterface $DB
     * @param string $refresh_token_table_name Like: schema.table_name
     * @param int $refresh_token_length
     * @throws \Exception `refresh_token_table_name` cannot be empty and must be string
     * @throws \Exception `refresh_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8
     */
    public function __construct(DBInterface $DB, $refresh_token_table_name, $refresh_token_length)
    {
        if (
            !$refresh_token_table_name ||
            !is_string($refresh_token_table_name)
        )
            throw new \Exception('`refresh_token_table_name` cannot be empty and must be string');

        $parts = explode('.', $refresh_token_table_name);
        if (count($parts) != 2)
            throw new \Exception('`refresh_token_table_name` name format must be like: schema.table_name');

        if (
            !$refresh_token_length ||
            !is_int($refresh_token_length) ||
            $refresh_token_length < 32 ||
            ($refresh_token_length % 8) != 0
        )
            throw new \Exception('`refresh_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8');

        $this->DB = $DB;
        $this->refresh_token_table_name = strtolower($refresh_token_table_name);
        $this->refresh_token_length = ($refresh_token_length / 2);
    }

    /**
     * Return SQL script of database structure
     *
     * @return string
     */
    public function getDBStructure()
    {
        $script = " CREATE TABLE " . $this->refresh_token_table_name . " (
                        refresh_token BINARY(" . $this->refresh_token_length . ") NOT NULL,
                        client_id VARCHAR(64) NOT NULL,
                        user_id BINARY(16) DEFAULT NULL,
                        expired_at DATETIME NOT NULL,
                        PRIMARY KEY (`refresh_token`) ); ";

        return $script;
    }

    /**
     * Create database structure if already not created
     *
     * @return bool return true when created otherwise false
     */
    public function createDBStructure()
    {
        $query = ' SELECT table_schema, 
                          table_name 
                     FROM information_schema.tables 
                    WHERE LOWER(CONCAT(table_schema, \'.\' ,table_name)) 
                        IN (:refresh_token_table_name) ';
        $values = [
            ':refresh_token_table_name' => str_replace('`', '', strtolower($this->refresh_token_table_name)),
        ];
        $tables = $this->DB->fetchColumn($query, $values);
        if (empty($tables)) {
            $query = $this->getDBStructure();
            $this->DB->importSQL($query);
            return true;
        }

        return false;
    }

    /**
     * Get refresh token details
     * refresh_token is case insensitive
     *
     * @param string $refresh_token
     * @return array
     */
    public function getRefreshToken($refresh_token)
    {
        $refresh_token = strtolower($refresh_token);
        $exp = $this->DB->getExpression();

        $query
            = " SELECT " . $exp->getUuid('refresh_token') . " refresh_token,
                           client_id,
                       " . $exp->getUuid('user_id') . " user_id,
                       " . $exp->getDate("expired_at") . " expired_at
                  FROM " . $this->refresh_token_table_name . "
                 WHERE " . $exp->getUuid('refresh_token') . " = :refresh_token ";
        $values = [
            ':refresh_token' => $refresh_token
        ];
        $row = $this->DB->fetchRow($query, $values);
        return $row;
    }

    /**
     * Get all expired refresh tokens
     *
     * @return array
     */
    public function getExpiredRefreshTokens()
    {
        $exp = $this->DB->getExpression();

        $query
            = " SELECT " . $exp->getUuid('refresh_token') . " refresh_token,
                            client_id,
                       " . $exp->getUuid('user_id') . " user_id,
                       " . $exp->getDate("expired_at") . " expired_at
                  FROM " . $this->refresh_token_table_name . "
                 WHERE " . $exp->getDate("expired_at") . " <= :expired_at ";
        $values = [
            ':expired_at' => date('Y-m-d H:i:s')
        ];
        $rows = $this->DB->fetchRows($query, $values);
        return $rows;
    }

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
    ) {
        $exp = $this->DB->getExpression();

        $data = [];
        $data['refresh_token'] = $exp->setUuid($refresh_token);
        $data['client_id'] = $client_id;
        $data['user_id'] = $exp->setUuid($user_id);
        $data['expired_at'] = $exp->setDate($expired_at);
        $this->DB->insert($this->refresh_token_table_name, $data);
    }

    /**
     * Delete refresh token details
     *
     * @param string $refresh_token
     * @return void
     */
    public function deleteRefreshToken($refresh_token)
    {
        $refresh_token = strtolower($refresh_token);
        $exp = $this->DB->getExpression();

        $query = " DELETE FROM " . $this->refresh_token_table_name . "
                  WHERE " . $exp->getUuid('refresh_token') . " = :refresh_token ";
        $values = [':refresh_token' => $refresh_token];
        $this->DB->delete($query, $values);
    }

    /**
     * Delete all expired refresh tokens
     *
     * @return void
     */
    public function deleteExpiredRefreshTokens()
    {
        $exp = $this->DB->getExpression();

        $query = " DELETE FROM " . $this->refresh_token_table_name . "
                    WHERE   " . $exp->getDate("expired_at") . " <= :expired_at ";
        $values = [
            ':expired_at' => date('Y-m-d H:i:s')
        ];
        $this->DB->delete($query, $values);
    }
}
