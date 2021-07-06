<?php

namespace FR\OAuth2\Storage\MySQL;

use FR\Db\DbInterface;
use FR\OAuth2\Storage\AccessTokensStorageInterface;

class AccessTokensStorage implements AccessTokensStorageInterface
{
    /**
     * @var object FR\Db\DbInterface
     */
    protected $DB;

    /**
     * Access token table name Like: schema.table_name
     *
     * @var string
     */
    protected $access_token_table_name;

    /**
     * Access token length
     *
     * @var int
     */
    protected $access_token_length;

    /**
     * Access token storage
     *
     * @param object FR\Db\DbInterface $DB
     * @param string $access_token_table_name Like: schema.table_name
     * @param int $access_token_length
     * @throws \Exception `access_token_table_name` cannot be empty and must be string
     * @throws \Exception `access_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8
     */
    public function __construct(DBInterface $DB, $access_token_table_name, $access_token_length)
    {
        if (
            !$access_token_table_name ||
            !is_string($access_token_table_name)
        )
            throw new \Exception('`access_token_table_name` cannot be empty and must be string');

        $parts = explode('.', $access_token_table_name);
        if (count($parts) != 2)
            throw new \Exception('`access_token_table_name` name format must be like: schema.table_name');

        if (
            !$access_token_length ||
            !is_int($access_token_length) ||
            $access_token_length < 32 ||
            ($access_token_length % 8) != 0
        )
            throw new \Exception('`access_token_length` cannot be empty and must be integer and must be greater than equal to 32 and must be divisible by 8');

        $this->DB = $DB;
        $this->access_token_table_name = strtolower($access_token_table_name);
        $this->access_token_length = ($access_token_length / 2);
    }

    /**
     * Return SQL script of database structure
     *
     * @return string
     */
    public function getDBStructure()
    {
        $script = " CREATE TABLE " . $this->access_token_table_name . " (
                        access_token BINARY(" . $this->access_token_length . ") NOT NULL,
                        client_id VARCHAR(64) NOT NULL,
                        user_id BINARY(16) DEFAULT NULL,
                        expired_at DATETIME NOT NULL,
                        PRIMARY KEY (`access_token`) ); ";

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
                        IN (:access_token_table_name) ';
        $values = [
            ':access_token_table_name' => str_replace('`', '', strtolower($this->access_token_table_name)),
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
     * Get access token details
     * access_token is case insensitive
     *
     * @param string $access_token
     * @return array
     */
    public function getAccessToken($access_token)
    {
        $access_token = strtolower($access_token);
        $exp = $this->DB->getExpression();

        $query
            = " SELECT " . $exp->getUuid('access_token') . " access_token,
                           client_id,
                       " . $exp->getUuid('user_id') . " user_id,
                       " . $exp->getDate("expired_at") . " expired_at
                  FROM " . $this->access_token_table_name . "
                 WHERE " . $exp->getUuid('access_token') . " = :access_token ";
        $values = [
            ':access_token' => $access_token
        ];
        $row = $this->DB->fetchRow($query, $values);
        return $row;
    }

    /**
     * Get all expired access tokens
     *
     * @return array
     */
    public function getExpiredAccessTokens()
    {
        $exp = $this->DB->getExpression();

        $query
            = " SELECT " . $exp->getUuid('access_token') . " access_token,
                            client_id,
                       " . $exp->getUuid('user_id') . " user_id,
                       " . $exp->getDate("expired_at") . " expired_at
                  FROM " . $this->access_token_table_name . "
                 WHERE " . $exp->getDate("expired_at") . " <= :expired_at ";
        $values = [
            ':expired_at' => date('Y-m-d H:i:s')
        ];
        $rows = $this->DB->fetchRows($query, $values);
        return $rows;
    }

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
    ) {
        $exp = $this->DB->getExpression();

        $data = [];
        $data['access_token'] = $exp->setUuid($access_token);
        $data['client_id'] = $client_id;
        $data['user_id'] = $exp->setUuid($user_id);
        $data['expired_at'] = $exp->setDate($expired_at);
        $this->DB->insert($this->access_token_table_name, $data);
    }

    /**
     * Delete access token details
     *
     * @param string $access_token
     * @return void
     */
    public function deleteAccessToken($access_token)
    {
        $access_token = strtolower($access_token);
        $exp = $this->DB->getExpression();

        $query = " DELETE FROM " . $this->access_token_table_name . "
                  WHERE " . $exp->getUuid('access_token') . " = :access_token ";
        $values = [':access_token' => $access_token];
        $this->DB->delete($query, $values);
    }

    /**
     * Delete all expired access tokens
     *
     * @return void
     */
    public function deleteExpiredAccessTokens()
    {
        $exp = $this->DB->getExpression();

        $query = " DELETE FROM " . $this->access_token_table_name . "
                    WHERE   " . $exp->getDate("expired_at") . " <= :expired_at ";
        $values = [
            ':expired_at' => date('Y-m-d H:i:s')
        ];
        $this->DB->delete($query, $values);
    }
}
