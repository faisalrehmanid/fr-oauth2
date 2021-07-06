<?php

namespace FR\OAuth2\Storage;

interface ClientsStorageInterface
{
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
    public function getClientById($client_id);
}
