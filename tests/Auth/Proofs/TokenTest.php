<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Proofs\Token;

class TokenTest extends TestCase
{
    protected Token $token;

    protected function setUp(): void
    {
        $this->token = new Token(32);
    }

    public function testGenerate()
    {
        $input = 'user123';
        $proof = $this->token->generate($input);

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertNotEquals($input, $proof);
        $this->assertEquals(32, strlen($proof)); // Default token length
    }

    public function testHash()
    {
        $proof = $this->token->generate('user123');
        $hash = $this->token->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertEquals(64, strlen($hash)); // SHA-256 produces a 64-character hex string
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash); // SHA-256 hex format
    }

    public function testVerify()
    {
        $proof = $this->token->generate('user123');
        $hash = $this->token->hash($proof);

        $this->assertTrue($this->token->verify($proof, $hash));
        $this->assertFalse($this->token->verify('wrongtoken', $hash));
    }
}
