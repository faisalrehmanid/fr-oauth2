<?php

namespace FR\OAuth2\Storage\Oracle;

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
        $this->access_token_table_name = strtoupper($access_token_table_name);
        $this->access_token_length = ($access_token_length / 2);
    }

    /**
     * Return SQL script of database structure
     *
     * @return string
     */
    public function getDBStructure()
    {
        $parts   = explode('.', $this->access_token_table_name);
        @$schema = $parts[0];
        @$table  = $parts[1];

        $script = " CREATE TABLE " . $this->access_token_table_name . "
                 (
                   ACCESS_TOKEN  RAW(" . $this->access_token_length . ") NOT NULL,
                   CLIENT_ID     VARCHAR2(64 CHAR)                       NOT NULL,
                   USER_ID       RAW(16),
                   EXPIRED_AT    DATE                                    NOT NULL
                 );
                 CREATE UNIQUE INDEX " . $this->access_token_table_name . "_PK ON " . $this->access_token_table_name . " (ACCESS_TOKEN);
                 ALTER TABLE " . $this->access_token_table_name . " ADD (
                   CONSTRAINT " . $table . "_PK
                   PRIMARY KEY
                   (ACCESS_TOKEN)
                   USING INDEX " . $this->access_token_table_name . "_PK
                   ENABLE VALIDATE 
                 ); ";

        return $script;
    }

    /**
     * Create database structure if already not created
     *
     * @return bool return true when created otherwise false
     */
    public function createDBStructure()
    {
        $query = ' SELECT OWNER, 
                          TABLE_NAME 
                    FROM ALL_TABLES
                        WHERE UPPER(OWNER || \'.\' || TABLE_NAME)
                                IN (:ACCESS_TOKEN_TABLE_NAME) ';
        $values = [
            ':ACCESS_TOKEN_TABLE_NAME' => str_replace('"', '', strtoupper($this->access_token_table_name)),
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
            = " SELECT " . $exp->getUuid('ACCESS_TOKEN') . " ACCESS_TOKEN,
                           CLIENT_ID,
                       " . $exp->getUuid('USER_ID') . " USER_ID,
                       " . $exp->getDate("EXPIRED_AT") . " EXPIRED_AT
                  FROM " . $this->access_token_table_name . "
                 WHERE " . $exp->getUuid('ACCESS_TOKEN') . " = :ACCESS_TOKEN ";
        $values = [
            ':ACCESS_TOKEN' => $access_token
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
            = " SELECT " . $exp->getUuid('ACCESS_TOKEN') . " ACCESS_TOKEN,
                           CLIENT_ID,
                       " . $exp->getUuid('USER_ID') . " USER_ID,
                       " . $exp->getDate("EXPIRED_AT") . " EXPIRED_AT
                FROM   " . $this->access_token_table_name . "
                WHERE  " . $exp->getDate("EXPIRED_AT") . " <= :EXPIRED_AT ";
        $values = [
            ':EXPIRED_AT' => date('Y-m-d H:i:s')
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
        $data['ACCESS_TOKEN'] = $exp->setUuid($access_token);
        $data['CLIENT_ID'] = $client_id;
        $data['USER_ID'] = $exp->setUuid($user_id);
        $data['EXPIRED_AT'] = $exp->setDate($expired_at);
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
                    WHERE " . $exp->getUuid('ACCESS_TOKEN') . " = :ACCESS_TOKEN ";
        $values = [
            ':ACCESS_TOKEN' => $access_token
        ];
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
                    WHERE   " . $exp->getDate("EXPIRED_AT") . " <= :EXPIRED_AT ";
        $values = [
            ':EXPIRED_AT' => date('Y-m-d H:i:s')
        ];
        $this->DB->delete($query, $values);
    }
}
