<?php

namespace FRUnitTest\OAuth2\Storage\Memory;

use PHPUnit\Framework\TestCase;
use FR\OAuth2\Storage\Memory\ClientsStorage;

class ClientsStorageTest extends TestCase
{
    protected static $MemoryTestAsset;
    protected static $clients;
    protected static $ClientsStorage;

    /**
     * This method is executed only once per class
     *
     * @return void
     */
    public static function setUpBeforeClass(): void
    {
        self::$MemoryTestAsset = new MemoryTestAsset();

        self::$clients = self::$MemoryTestAsset->getClients();
        self::$ClientsStorage = self::$MemoryTestAsset->getClientsStorage();
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Memory\ClientsStorage::__construct
     * 
     * @return void
     */
    public function constructor()
    {
        // `clients` cannot be empty
        $exception = false;
        try {
            new ClientsStorage([]);
        } catch (\Exception $expected) {
            $exception = true;
        }
        $this->assertTrue($exception, 'Exception not thrown: `clients` cannot be empty');
    }

    /**
     * @test
     * @covers FR\OAuth2\Storage\Memory\ClientsStorage::getClientById
     * 
     * @return void
     */
    public function getClientById()
    {
        $test = self::$clients;
        foreach ($test as $i => $param) {
            $row = invokeMethod(
                self::$ClientsStorage,
                'getClientById',
                [
                    strtoupper($param['client_id']),
                ]
            );

            $this->assertArrayHasKey('client_id', $row);
            $this->assertArrayHasKey('client_secret', $row);

            $this->assertEquals($param['client_id'], $row['client_id']);
            $this->assertEquals($param['client_secret'], $row['client_secret']);
        }

        // When not found
        $row = invokeMethod(
            self::$ClientsStorage,
            'getClientById',
            [
                '---INVALID-CLIENT-ID---'
            ]
        );
        $this->assertIsArray($row);
        $this->assertEmpty($row);
    }
}
