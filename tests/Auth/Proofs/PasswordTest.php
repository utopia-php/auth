<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Algorithms\Argon2;
use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Algorithms\MD5;
use Utopia\Auth\Algorithms\PHPass;
use Utopia\Auth\Algorithms\Scrypt;
use Utopia\Auth\Algorithms\ScryptModified;
use Utopia\Auth\Algorithms\Sha;
use Utopia\Auth\Proofs\Password;

class PasswordTest extends TestCase
{
    protected Password $password;

    protected Password $legacyPassword;

    protected Bcrypt $bcrypt;

    protected function setUp(): void
    {
        // Test new constructor with auto-initialized algorithms
        $this->password = new Password();

        // Test legacy constructor with explicit algorithms
        $this->bcrypt = new Bcrypt();
        $this->legacyPassword = new Password(['bcrypt' => $this->bcrypt]);
    }

    public function testGenerate()
    {
        $proof = $this->password->generate();

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertEquals(16, strlen($proof)); // Default length
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+$/', $proof);
    }

    public function testGenerateWithCustomLength()
    {
        $this->password->setLength(20);
        $proof = $this->password->generate();
        $this->assertEquals(20, strlen($proof));
    }

    public function testGenerateWithCustomCharset()
    {
        $this->password->setCharset('abcdef123456');
        $proof = $this->password->generate();
        $this->assertMatchesRegularExpression('/^[abcdef123456]+$/', $proof);
    }

    public function testSetLengthValidation()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Password length must be at least 8 characters');
        $this->password->setLength(7);
    }

    public function testSetCharsetValidation()
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Password charset must contain at least 10 characters');
        $this->password->setCharset('123456789');
    }

    public function testHash()
    {
        $proof = $this->password->generate();
        $hash = $this->password->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$argon2id$', $hash); // Default is now argon2
    }

    public function testVerify()
    {
        $proof = $this->password->generate();
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
        $this->assertFalse($this->password->verify('wrongpassword', $hash));
    }

    public function testAddAlgorithm()
    {
        $newBcrypt = new Bcrypt(['cost' => 8]);
        $this->password->addAlgorithm('bcrypt-8', $newBcrypt);

        // Verify the algorithm was added
        $algorithm = $this->password->getAlgorithmByName('bcrypt-8');
        $this->assertInstanceOf(Bcrypt::class, $algorithm);

        // Test that the algorithm works
        $proof = $this->password->generate();
        $this->password->setAlgorithm($algorithm);
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
        $this->assertFalse($this->password->verify('wrongpassword', $hash));
    }

    public function testDefaultAlgorithms()
    {
        // Test that all default algorithms are initialized
        $this->assertInstanceOf(Argon2::class, $this->password->getAlgorithmByName(Password::ARGON2));
        $this->assertInstanceOf(Bcrypt::class, $this->password->getAlgorithmByName(Password::BCRYPT));
        $this->assertInstanceOf(Scrypt::class, $this->password->getAlgorithmByName(Password::SCRYPT));
        $this->assertInstanceOf(ScryptModified::class, $this->password->getAlgorithmByName(Password::SCRYPT_MODIFIED));
        $this->assertInstanceOf(Sha::class, $this->password->getAlgorithmByName(Password::SHA));
        $this->assertInstanceOf(MD5::class, $this->password->getAlgorithmByName(Password::MD5));
        $this->assertInstanceOf(PHPass::class, $this->password->getAlgorithmByName(Password::PHPASS));
    }

    public function testRemoveAlgorithm()
    {
        // First try to remove the current algorithm (should fail)
        $this->expectException(\Exception::class);
        $this->password->removeAlgorithm(Password::ARGON2); // Argon2 is the default current algorithm
    }

    public function testRemoveNonCurrentAlgorithm()
    {
        // Should be able to remove a non-current algorithm
        $this->password->removeAlgorithm(Password::MD5);

        // Verify it was removed
        $this->expectException(\Exception::class);
        $this->password->getAlgorithmByName(Password::MD5);
    }

    public function testGetAlgorithm()
    {
        $algorithm = $this->password->getAlgorithmByName(Password::BCRYPT);
        $this->assertInstanceOf(Bcrypt::class, $algorithm);

        $this->expectException(\Exception::class);
        $this->password->getAlgorithmByName('non-existent-algorithm');
    }

    public function testAllAlgorithmsWork()
    {
        $proof = $this->password->generate();
        $algorithms = [
            Password::ARGON2,
            Password::BCRYPT,
            Password::SCRYPT,
            Password::SCRYPT_MODIFIED,
            Password::SHA,
            Password::MD5,
            Password::PHPASS,
        ];

        foreach ($algorithms as $algo) {
            $algorithm = $this->password->getAlgorithmByName($algo);
            $this->password->setAlgorithm($algorithm);
            $hash = $this->password->hash($proof);
            $this->assertTrue($this->password->verify($proof, $hash), "Algorithm {$algo} failed verification");
            $this->assertFalse($this->password->verify('wrongpassword', $hash), "Algorithm {$algo} failed wrong password test");
        }
    }

    public function testLegacyConstructor()
    {
        $proof = $this->password->generate();
        $hash = $this->legacyPassword->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$2y$', $hash);
        $this->assertTrue($this->legacyPassword->verify($proof, $hash));

        // Verify that only the specified algorithm is available
        $this->expectException(\Exception::class);
        $this->legacyPassword->getAlgorithmByName(Password::ARGON2);
    }
}
