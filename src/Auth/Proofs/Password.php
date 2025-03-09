<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Hash;
use Utopia\Auth\Hashes\Argon2;
use Utopia\Auth\Hashes\Bcrypt;
use Utopia\Auth\Hashes\MD5;
use Utopia\Auth\Hashes\PHPass;
use Utopia\Auth\Hashes\Scrypt;
use Utopia\Auth\Hashes\ScryptModified;
use Utopia\Auth\Hashes\Sha;
use Utopia\Auth\Proof;

class Password extends Proof
{
    public const ARGON2 = 'argon2';

    public const BCRYPT = 'bcrypt';

    public const SCRYPT = 'scrypt';

    public const SCRYPT_MODIFIED = 'scrypt-modified';

    public const SHA = 'sha';

    public const MD5 = 'md5';

    public const PHPASS = 'phpass';

    /**
     * @var array<string, Hash>
     */
    protected array $hashes = [];

    protected int $defaultLength = 16;

    protected string $defaultCharset = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?';

    /**
     * @param  array<string, Hash>  $hashes
     *
     * @throws \Exception
     */
    public function __construct(array $hashes = [])
    {
        parent::__construct();

        // Initialize default hashes if no hashes were provided
        if ($hashes === []) {
            $hashes = [
                self::ARGON2 => new Argon2(),
                self::BCRYPT => new Bcrypt(),
                self::SCRYPT => new Scrypt(),
                self::SCRYPT_MODIFIED => new ScryptModified(),
                self::SHA => new Sha(),
                self::MD5 => new MD5(),
                self::PHPASS => new PHPass(),
            ];
        }

        $this->hashes = $hashes;
        $this->hash = reset($hashes); // Set the first hash as the default one
    }

    /**
     * Add a new hashing hash
     *
     * @param  string  $name
     * @param  Hash  $hash
     * @return self
     */
    public function addHash(string $name, Hash $hash): self
    {
        $this->hashes[$name] = $hash;

        return $this;
    }

    /**
     * Remove a hashing hash
     *
     * @param  string  $name
     * @return self
     *
     * @throws \Exception
     */
    public function removeHash(string $name): self
    {
        if (! isset($this->hashes[$name])) {
            throw new \Exception("Hash '{$name}' not found");
        }

        if ($this->hash === $this->hashes[$name]) {
            throw new \Exception('Cannot remove current hash');
        }

        unset($this->hashes[$name]);

        return $this;
    }

    /**
     * Get a specific hashing hash by name
     *
     * @param  string  $name
     * @return Hash
     *
     * @throws \Exception
     */
    public function getHashByName(string $name): Hash
    {
        if (! isset($this->hashes[$name])) {
            throw new \Exception("Hash '{$name}' not found");
        }

        return $this->hashes[$name];
    }

    /**
     * Set password generation length
     *
     * @param  int  $length
     * @return self
     *
     * @throws \Exception
     */
    public function setLength(int $length): self
    {
        if ($length < 8) {
            throw new \Exception('Password length must be at least 8 characters');
        }
        $this->defaultLength = $length;

        return $this;
    }

    /**
     * Set password generation charset
     *
     * @param  string  $charset
     * @return self
     *
     * @throws \Exception
     */
    public function setCharset(string $charset): self
    {
        if (strlen($charset) < 10) {
            throw new \Exception('Password charset must contain at least 10 characters');
        }
        $this->defaultCharset = $charset;

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function generate(): string
    {
        $password = '';
        $max = strlen($this->defaultCharset) - 1;

        if ($max < 0) {
            throw new \Exception('Password charset is empty');
        }

        for ($i = 0; $i < $this->defaultLength; $i++) {
            $password .= $this->defaultCharset[random_int(0, $max)];
        }

        return $password;
    }
}
