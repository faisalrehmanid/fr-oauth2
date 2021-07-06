<?php

namespace FR\OAuth2\Storage\Memory;

use FR\OAuth2\Storage\ClientsStorageInterface;

class ClientsStorage implements ClientsStorageInterface
{
    protected $clients = [];

    public function __construct(array $clients)
    {
        if (empty($clients))
            throw new \Exception('`clients` cannot be empty');

        $this->clients = $clients;
    }

    /**
     * Get client details by client_id
     * client_id is case insensitive
     * 
     * @param string $client_id
     * @param string $client_secret
     * @return array [ 'client_id' => 'client_id',
     *                 'client_secret' => 'client_secret']
     * 
     */
    public function getClientById($client_id)
    {
        foreach ($this->clients as $i => $client) {
            if (strtolower($client['client_id']) == strtolower($client_id))
                return $client;
        }

        return [];
    }
}
