<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\Sha;
use Utopia\Auth\Proofs\Token;

class TokenTest extends TestCase
{
    protected Token $token;

    protected function setUp(): void
    {
        $this->token = new Token(32);
        $this->token->setAlgorithm(new Sha());
        $this->token->getAlgorithm()->setVersion('sha256');
    }

    public function testGenerate()
    {
        $proof = $this->token->generate();

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertEquals(32, strlen($proof)); // Default token length
    }

    public function testHash()
    {
        $proof = $this->token->generate();
        $hash = $this->token->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertEquals(64, strlen($hash)); // SHA-256 produces a 64-character hex string
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $hash); // SHA-256 hex format
    }

    public function testVerify()
    {
        $proof = $this->token->generate();
        $hash = $this->token->hash($proof);

        $this->assertTrue($this->token->verify($proof, $hash));
        $this->assertFalse($this->token->verify('wrongtoken', $hash));
    }

    public function testGetLength()
    {
        $this->assertEquals(32, $this->token->getLength());

        $token = new Token(64);
        $this->assertEquals(64, $token->getLength());
    }

    public function testSetLength()
    {
        $this->token->setLength(64);
        $this->assertEquals(64, $this->token->getLength());

        $proof = $this->token->generate();
        $this->assertEquals(64, strlen($proof));
    }

    public function testSetLengthInvalid()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Token length must be greater than 0');
        $this->token->setLength(0);
    }
}
