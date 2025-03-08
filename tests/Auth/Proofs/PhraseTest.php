<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Proofs\Phrase;

class PhraseTest extends TestCase
{
    protected Phrase $phrase;

    protected function setUp(): void
    {
        $this->phrase = new Phrase(new Bcrypt());
    }

    public function testGenerate()
    {
        $proof = $this->phrase->generate();

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertStringContainsString(' ', $proof); // Should contain spaces between words
        $this->assertMatchesRegularExpression('/^[a-zA-Z\s]+$/', $proof); // Letters (both cases) and spaces
    }

    public function testHash()
    {
        $proof = $this->phrase->generate();
        $hash = $this->phrase->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$argon2id$', $hash);
    }

    public function testVerify()
    {
        $proof = $this->phrase->generate();
        $hash = $this->phrase->hash($proof);

        $this->assertTrue($this->phrase->verify($proof, $hash));
        $this->assertFalse($this->phrase->verify('wrong phrase here', $hash));
    }
}
