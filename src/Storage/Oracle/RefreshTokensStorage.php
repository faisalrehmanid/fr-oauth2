<?php

namespace FR\OAuth2\Storage\Oracle;

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
        $this->refresh_token_table_name = strtoupper($refresh_token_table_name);
        $this->refresh_token_length = ($refresh_token_length / 2);
    }

    /**
     * Return SQL script of database structure
     *
     * @return string
     */
    public function getDBStructure()
    {
        $parts   = explode('.', $this->refresh_token_table_name);
        @$schema = $parts[0];
        @$table  = $parts[1];

        $script = " CREATE TABLE " . $this->refresh_token_table_name . "
                 (
                   REFRESH_TOKEN  RAW(" . $this->refresh_token_length . ") NOT NULL,
                   CLIENT_ID      VARCHAR2(64 CHAR)                        NOT NULL,
                   USER_ID        RAW(16),
                   EXPIRED_AT     DATE                                     NOT NULL
                 );
                 CREATE UNIQUE INDEX " . $this->refresh_token_table_name . "_PK ON " . $this->refresh_token_table_name . " (REFRESH_TOKEN);
                 ALTER TABLE " . $this->refresh_token_table_name . " ADD (
                   CONSTRAINT " . $table . "_PK
                   PRIMARY KEY
                   (REFRESH_TOKEN)
                   USING INDEX " . $this->refresh_token_table_name . "_PK
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
                                IN (:REFRESH_TOKEN_TABLE_NAME) ';
        $values = [
            ':REFRESH_TOKEN_TABLE_NAME' => str_replace('"', '', strtoupper($this->refresh_token_table_name)),
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
            = " SELECT " . $exp->getUuid('REFRESH_TOKEN') . " REFRESH_TOKEN,
                           CLIENT_ID,
                       " . $exp->getUuid('USER_ID') . " USER_ID,
                       " . $exp->getDate("EXPIRED_AT") . " EXPIRED_AT
                  FROM " . $this->refresh_token_table_name . "
                 WHERE " . $exp->getUuid('REFRESH_TOKEN') . " = :REFRESH_TOKEN ";
        $values = [
            ':REFRESH_TOKEN' => $refresh_token
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
            = " SELECT " . $exp->getUuid('REFRESH_TOKEN') . " REFRESH_TOKEN,
                           CLIENT_ID,
                       " . $exp->getUuid('USER_ID') . " USER_ID,
                       " . $exp->getDate("EXPIRED_AT") . " EXPIRED_AT
                FROM   " . $this->refresh_token_table_name . "
                WHERE  " . $exp->getDate("EXPIRED_AT") . " <= :EXPIRED_AT ";
        $values = [
            ':EXPIRED_AT' => date('Y-m-d H:i:s')
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
        $data['REFRESH_TOKEN'] = $exp->setUuid($refresh_token);
        $data['CLIENT_ID'] = $client_id;
        $data['USER_ID'] = $exp->setUuid($user_id);
        $data['EXPIRED_AT'] = $exp->setDate($expired_at);
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
                    WHERE " . $exp->getUuid('REFRESH_TOKEN') . " = :REFRESH_TOKEN ";
        $values = [
            ':REFRESH_TOKEN' => $refresh_token
        ];
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
                    WHERE   " . $exp->getDate("EXPIRED_AT") . " <= :EXPIRED_AT ";
        $values = [
            ':EXPIRED_AT' => date('Y-m-d H:i:s')
        ];
        $this->DB->delete($query, $values);
    }
}
