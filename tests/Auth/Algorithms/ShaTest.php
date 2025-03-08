<?php

namespace Utopia\Tests\Auth\Algorithms;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\Sha;

class ShaTest extends TestCase
{
    protected Sha $sha;

    protected function setUp(): void
    {
        $this->sha = new Sha();
    }

    public function testHash()
    {
        $password = 'test123';
        $hash = $this->sha->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertTrue($this->sha->verify($password, $hash));
        $this->assertFalse($this->sha->verify('wrongpassword', $hash));
    }

    public function testCustomVersion()
    {
        $this->sha->setVersion(Sha::SHA256);
        $password = 'test123';
        $hash = $this->sha->hash($password);

        $this->assertTrue($this->sha->verify($password, $hash));
    }

    public function testInvalidVersion()
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->sha->setVersion('invalid-version');
    }
}
