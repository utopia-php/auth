<?php

namespace Utopia\Tests\Auth\Hashes;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Hashes\Sha;

class ShaTest extends TestCase
{
    protected Sha $sha;

    protected function setUp(): void
    {
        $this->sha = new Sha();
    }

    public function testHash(): void
    {
        $password = 'test123';
        $hash = $this->sha->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertTrue($this->sha->verify($password, $hash));
        $this->assertFalse($this->sha->verify('wrongpassword', $hash));
    }

    public function testCustomVersion(): void
    {
        $this->sha->setVersion(Sha::SHA256);
        $password = 'test123';
        $hash = $this->sha->hash($password);

        $this->assertTrue($this->sha->verify($password, $hash));
    }

    public function testInvalidVersion(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->sha->setVersion('invalid-version');
    }

    public function testGetName(): void
    {
        $this->assertEquals('sha', $this->sha->getName());
    }
}
