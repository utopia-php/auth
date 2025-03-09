<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Hashes\Argon2;
use Utopia\Auth\Hashes\Bcrypt;
use Utopia\Auth\Hashes\MD5;
use Utopia\Auth\Hashes\PHPass;
use Utopia\Auth\Hashes\Scrypt;
use Utopia\Auth\Hashes\ScryptModified;
use Utopia\Auth\Hashes\Sha;
use Utopia\Auth\Proofs\Password;

class PasswordTest extends TestCase
{
    protected Password $password;

    protected Password $legacyPassword;

    protected Bcrypt $bcrypt;

    protected function setUp(): void
    {
        // Test new constructor with auto-initialized hashes
        $this->password = new Password();

        // Test legacy constructor with explicit hashes
        $this->bcrypt = new Bcrypt();
        $this->legacyPassword = new Password(['bcrypt' => $this->bcrypt]);
    }

    public function testGenerate(): void
    {
        $proof = $this->password->generate();

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertEquals(16, strlen($proof)); // Default length
        $this->assertMatchesRegularExpression('/^[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]+$/', $proof);
    }

    public function testGenerateWithCustomLength(): void
    {
        $this->password->setLength(20);
        $proof = $this->password->generate();
        $this->assertEquals(20, strlen($proof));
    }

    public function testGenerateWithCustomCharset(): void
    {
        $this->password->setCharset('abcdef123456');
        $proof = $this->password->generate();
        $this->assertMatchesRegularExpression('/^[abcdef123456]+$/', $proof);
    }

    public function testSetLengthValidation(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Password length must be at least 8 characters');
        $this->password->setLength(7);
    }

    public function testSetCharsetValidation(): void
    {
        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('Password charset must contain at least 10 characters');
        $this->password->setCharset('123456789');
    }

    public function testHash(): void
    {
        $proof = $this->password->generate();
        $hash = $this->password->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$argon2id$', $hash); // Default is now argon2
    }

    public function testVerify(): void
    {
        $proof = $this->password->generate();
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
        $this->assertFalse($this->password->verify('wrongpassword', $hash));
    }

    public function testAddHash(): void
    {
        $newBcrypt = new Bcrypt();
        $newBcrypt->setCost(8);
        $this->password->addHash('bcrypt-8', $newBcrypt);

        // Verify the hash was added
        $hash = $this->password->getHashByName('bcrypt-8');
        $this->assertInstanceOf(Bcrypt::class, $hash);

        // Test that the hash works
        $proof = $this->password->generate();
        $this->password->setHash($hash);
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
        $this->assertFalse($this->password->verify('wrongpassword', $hash));
    }

    public function testDefaultHashes(): void
    {
        // Test that all default hashes are initialized
        $this->assertInstanceOf(Argon2::class, $this->password->getHashByName(Password::ARGON2));
        $this->assertInstanceOf(Bcrypt::class, $this->password->getHashByName(Password::BCRYPT));
        $this->assertInstanceOf(Scrypt::class, $this->password->getHashByName(Password::SCRYPT));
        $this->assertInstanceOf(ScryptModified::class, $this->password->getHashByName(Password::SCRYPT_MODIFIED));
        $this->assertInstanceOf(Sha::class, $this->password->getHashByName(Password::SHA));
        $this->assertInstanceOf(MD5::class, $this->password->getHashByName(Password::MD5));
        $this->assertInstanceOf(PHPass::class, $this->password->getHashByName(Password::PHPASS));
    }

    public function testRemoveHash(): void
    {
        // First try to remove the current hash (should fail)
        $this->expectException(\Exception::class);
        $this->password->removeHash(Password::ARGON2); // Argon2 is the default current hash
    }

    public function testRemoveNonCurrentHash(): void
    {
        // Should be able to remove a non-current hash
        $this->password->removeHash(Password::MD5);

        // Verify it was removed
        $this->expectException(\Exception::class);
        $this->password->getHashByName(Password::MD5);
    }

    public function testGetHash(): void
    {
        $hash = $this->password->getHashByName(Password::BCRYPT);
        $this->assertInstanceOf(Bcrypt::class, $hash);

        $this->expectException(\Exception::class);
        $this->password->getHashByName('non-existent-hash');
    }

    public function testAllHashesWork(): void
    {
        $proof = $this->password->generate();
        $hashes = [
            Password::ARGON2,
            Password::BCRYPT,
            Password::SCRYPT,
            Password::SCRYPT_MODIFIED,
            Password::SHA,
            Password::MD5,
            Password::PHPASS,
        ];

        foreach ($hashes as $algo) {
            $hash = $this->password->getHashByName($algo);
            $this->password->setHash($hash);
            $hash = $this->password->hash($proof);
            $this->assertTrue($this->password->verify($proof, $hash), "Hash {$algo} failed verification");
            $this->assertFalse($this->password->verify('wrongpassword', $hash), "Hash {$algo} failed wrong password test");
        }
    }

    public function testLegacyConstructor(): void
    {
        $proof = $this->password->generate();
        $hash = $this->legacyPassword->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$2y$', $hash);
        $this->assertTrue($this->legacyPassword->verify($proof, $hash));

        // Verify that only the specified hash is available
        $this->expectException(\Exception::class);
        $this->legacyPassword->getHashByName(Password::ARGON2);
    }
}
