<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Proofs\Code;

class CodeTest extends TestCase
{
    protected Code $code;

    protected function setUp(): void
    {
        $this->code = new Code(); // Using default length of 6
    }

    public function testGenerate()
    {
        $input = 'user@example.com';
        $proof = $this->code->generate($input);

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertNotEquals($input, $proof);
        $this->assertEquals(6, strlen($proof)); // Default code length
        $this->assertMatchesRegularExpression('/^[0-9]{6}$/', $proof);
    }

    public function testHash()
    {
        $proof = $this->code->generate('user@example.com');
        $hash = $this->code->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertEquals(64, strlen($hash)); // SHA256 hash length
    }

    public function testVerify()
    {
        $proof = $this->code->generate('user@example.com');
        $hash = $this->code->hash($proof);

        $this->assertTrue($this->code->verify($proof, $hash));
        $this->assertFalse($this->code->verify('000000', $hash));
    }

    public function testCustomLength()
    {
        $code = new Code(8);
        $proof = $code->generate('test');

        $this->assertEquals(8, strlen($proof));
        $this->assertMatchesRegularExpression('/^[0-9]{8}$/', $proof);
    }
}
