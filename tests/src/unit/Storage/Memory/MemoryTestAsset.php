<?php

namespace FRUnitTest\OAuth2\Storage\Memory;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\Memory\ClientsStorage;

class MemoryTestAsset extends TestCase
{
    public function getClients()
    {
        $clients = [
            [
                'client_id' => 'client-id-1',
                'client_secret' => 'client-secret-1'
            ],
            [
                'client_id' => 'client-id-2',
                'client_secret' => 'client-secret-2'
            ],
            [
                'client_id' => 'client-id-3',
                'client_secret' => 'client-secret-3'
            ]
        ];

        return $clients;
    }

    public function getClientsStorage()
    {
        $clients = $this->getClients();

        $ClientsStorage = new ClientsStorage($clients);
        return $ClientsStorage;
    }
}
