<?php

namespace Utopia\Tests\Auth\Algorithms;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\Bcrypt;

class BcryptTest extends TestCase
{
    protected Bcrypt $bcrypt;

    protected function setUp(): void
    {
        $this->bcrypt = new Bcrypt();
    }

    public function testHash()
    {
        $password = 'test123';
        $hash = $this->bcrypt->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$2y$', $hash);
        $this->assertTrue($this->bcrypt->verify($password, $hash));
        $this->assertFalse($this->bcrypt->verify('wrongpassword', $hash));
    }
}
