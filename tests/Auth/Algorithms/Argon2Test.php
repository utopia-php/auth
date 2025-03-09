<?php

namespace Utopia\Tests\Auth\Hashes;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Hashes\Argon2;

class Argon2Test extends TestCase
{
    protected Argon2 $argon2;

    protected function setUp(): void
    {
        $this->argon2 = new Argon2();
    }

    public function testHash(): void
    {
        $password = 'test123';
        $hash = $this->argon2->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$argon2id$', $hash);
        $this->assertTrue($this->argon2->verify($password, $hash));
        $this->assertFalse($this->argon2->verify('wrongpassword', $hash));
    }

    public function testMemoryCost(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->argon2->setMemoryCost(1); // Should throw exception for too low memory cost
    }

    public function testValidMemoryCost(): void
    {
        $cost = PASSWORD_ARGON2_DEFAULT_MEMORY_COST + 1024;
        $this->argon2->setMemoryCost($cost);

        // Test that the new memory cost is being used by verifying a hash
        $password = 'test123';
        $hash = $this->argon2->hash($password);
        $this->assertTrue($this->argon2->verify($password, $hash));
    }

    public function testTimeCost(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->argon2->setTimeCost(0); // Should throw exception for too low time cost
    }

    public function testValidTimeCost(): void
    {
        $cost = PASSWORD_ARGON2_DEFAULT_TIME_COST + 1;
        $this->argon2->setTimeCost($cost);

        // Test that the new time cost is being used by verifying a hash
        $password = 'test123';
        $hash = $this->argon2->hash($password);
        $this->assertTrue($this->argon2->verify($password, $hash));
    }

    public function testThreads(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->argon2->setThreads(0); // Should throw exception for too low thread count
    }

    public function testValidThreads(): void
    {
        $threads = PASSWORD_ARGON2_DEFAULT_THREADS + 1;
        $this->argon2->setThreads($threads);

        // Test that the new thread count is being used by verifying a hash
        $password = 'test123';
        $hash = $this->argon2->hash($password);
        $this->assertTrue($this->argon2->verify($password, $hash));
    }

    public function testGetName(): void
    {
        $this->assertEquals('argon2', $this->argon2->getName());
    }
}
