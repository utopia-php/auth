<?php

namespace Utopia\Tests\Auth\Hashes;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Hashes\Scrypt;

class ScryptTest extends TestCase
{
    protected Scrypt $scrypt;

    protected function setUp(): void
    {
        $this->scrypt = new Scrypt();
    }

    public function testHash(): void
    {
        $password = 'test123';
        $hash = $this->scrypt->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertTrue($this->scrypt->verify($password, $hash));
        $this->assertFalse($this->scrypt->verify('wrongpassword', $hash));
    }

    public function testCustomOptions(): void
    {
        $this->scrypt->setCpuCost(16)
            ->setMemoryCost(15)
            ->setParallelCost(2)
            ->setLength(128)
            ->setSalt('custom-salt');

        $password = 'test123';
        $hash = $this->scrypt->hash($password);

        $this->assertTrue($this->scrypt->verify($password, $hash));
    }
}
