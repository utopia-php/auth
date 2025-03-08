<?php

namespace Utopia\Tests\Auth\Algorithms;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\MD5;

class MD5Test extends TestCase
{
    protected MD5 $md5;

    protected function setUp(): void
    {
        $this->md5 = new MD5();
    }

    public function testHash()
    {
        $password = 'test123';
        $hash = $this->md5->hash($password);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertEquals(32, strlen($hash));
        $this->assertEquals(md5($password), $hash);
        $this->assertTrue($this->md5->verify($password, $hash));
        $this->assertFalse($this->md5->verify('wrongpassword', $hash));
    }

    public function testMultipleHashes()
    {
        $passwords = ['test123', 'password123', '!@#$%^&*()'];

        foreach ($passwords as $password) {
            $hash = $this->md5->hash($password);
            $this->assertEquals(md5($password), $hash);
            $this->assertTrue($this->md5->verify($password, $hash));
        }
    }

    public function testEmptyString()
    {
        $password = '';
        $hash = $this->md5->hash($password);

        $this->assertEquals(md5(''), $hash);
        $this->assertTrue($this->md5->verify($password, $hash));
    }

    public function testSpecialCharacters()
    {
        $password = '!@#$%^&*()_+-=[]{}|;:,.<>?';
        $hash = $this->md5->hash($password);

        $this->assertEquals(md5($password), $hash);
        $this->assertTrue($this->md5->verify($password, $hash));
    }

    public function testUnicodeCharacters()
    {
        $password = 'Hello 世界';
        $hash = $this->md5->hash($password);

        $this->assertEquals(md5($password), $hash);
        $this->assertTrue($this->md5->verify($password, $hash));
    }
}
