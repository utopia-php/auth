<?php

namespace Utopia\Tests\Auth\Proofs;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Proofs\Password;
use Utopia\Auth\Algorithms\Argon2;
use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Algorithms\MD5;
use Utopia\Auth\Algorithms\PHPass;
use Utopia\Auth\Algorithms\Scrypt;
use Utopia\Auth\Algorithms\ScryptModified;
use Utopia\Auth\Algorithms\Sha;

class PasswordTest extends TestCase
{
    protected Password $password;
    protected Password $legacyPassword;
    protected Bcrypt $bcrypt;

    protected function setUp(): void
    {
        // Test legacy constructor with explicit algorithms
        $this->bcrypt = new Bcrypt();
        $this->legacyPassword = new Password('bcrypt', ['bcrypt' => $this->bcrypt]);

        // Test new constructor with auto-initialized algorithms
        $this->password = new Password();
    }

    public function testGenerate()
    {
        $input = 'test123';
        $proof = $this->password->generate($input);

        $this->assertNotEmpty($proof);
        $this->assertIsString($proof);
        $this->assertEquals($input, $proof);
    }

    public function testHash()
    {
        $proof = 'test123';
        $hash = $this->password->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$argon2id$', $hash); // Default is now argon2
    }

    public function testVerify()
    {
        $proof = 'test123';
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
        $this->assertFalse($this->password->verify('wrongpassword', $hash));
    }

    public function testAddAlgorithm()
    {
        $newBcrypt = new Bcrypt(['cost' => 8]);
        $this->password->addAlgorithm('bcrypt-8', $newBcrypt);
        $this->password->setDefaultAlgorithm('bcrypt-8');

        $proof = 'test123';
        $hash = $this->password->hash($proof);

        $this->assertTrue($this->password->verify($proof, $hash));
    }

    public function testDefaultAlgorithms()
    {
        // Test that all default algorithms are initialized
        $this->assertInstanceOf(Argon2::class, $this->password->getAlgorithm(Password::ARGON2));
        $this->assertInstanceOf(Bcrypt::class, $this->password->getAlgorithm(Password::BCRYPT));
        $this->assertInstanceOf(Scrypt::class, $this->password->getAlgorithm(Password::SCRYPT));
        $this->assertInstanceOf(ScryptModified::class, $this->password->getAlgorithm(Password::SCRYPT_MODIFIED));
        $this->assertInstanceOf(Sha::class, $this->password->getAlgorithm(Password::SHA));
        $this->assertInstanceOf(MD5::class, $this->password->getAlgorithm(Password::MD5));
        $this->assertInstanceOf(PHPass::class, $this->password->getAlgorithm(Password::PHPASS));
    }

    public function testRemoveAlgorithm()
    {
        $this->expectException(\Exception::class);
        $this->password->removeAlgorithm(Password::ARGON2); // Should throw as it's the default

        $this->password->setDefaultAlgorithm(Password::BCRYPT);
        $this->password->removeAlgorithm(Password::ARGON2); // Should work now
        
        $this->expectException(\Exception::class);
        $this->password->getAlgorithm(Password::ARGON2); // Should throw as algorithm was removed
    }

    public function testGetAlgorithm()
    {
        $algorithm = $this->password->getAlgorithm(Password::BCRYPT);
        $this->assertInstanceOf(Bcrypt::class, $algorithm);

        $this->expectException(\Exception::class);
        $this->password->getAlgorithm('non-existent-algorithm');
    }

    public function testAllAlgorithmsWork()
    {
        $proof = 'test123';
        $algorithms = [
            Password::ARGON2,
            Password::BCRYPT,
            Password::SCRYPT,
            Password::SCRYPT_MODIFIED,
            Password::SHA,
            Password::MD5,
            Password::PHPASS
        ];

        foreach ($algorithms as $algo) {
            $this->password->setDefaultAlgorithm($algo);
            $hash = $this->password->hash($proof);
            $this->assertTrue($this->password->verify($proof, $hash), "Algorithm {$algo} failed verification");
            $this->assertFalse($this->password->verify('wrongpassword', $hash), "Algorithm {$algo} failed wrong password test");
        }
    }

    public function testLegacyConstructor()
    {
        $proof = 'test123';
        $hash = $this->legacyPassword->hash($proof);

        $this->assertNotEmpty($hash);
        $this->assertIsString($hash);
        $this->assertStringStartsWith('$2y$', $hash);
        $this->assertTrue($this->legacyPassword->verify($proof, $hash));
    }
} 