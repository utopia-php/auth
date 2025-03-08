<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Algorithm;
use Utopia\Auth\Algorithms\Argon2;
use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Algorithms\MD5;
use Utopia\Auth\Algorithms\PHPass;
use Utopia\Auth\Algorithms\Scrypt;
use Utopia\Auth\Algorithms\ScryptModified;
use Utopia\Auth\Algorithms\Sha;
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
     * @var array<string, Algorithm>
     */
    protected array $algorithms = [];

    /**
     * @param  array<string, Algorithm>  $algorithms
     *
     * @throws \Exception
     */
    public function __construct(array $algorithms = [])
    {
        parent::__construct();

        // Initialize default algorithms if none provided
        if (empty($algorithms)) {
            $algorithms = [
                self::ARGON2 => new Argon2(),
                self::BCRYPT => new Bcrypt(),
                self::SCRYPT => new Scrypt(),
                self::SCRYPT_MODIFIED => new ScryptModified(),
                self::SHA => new Sha(),
                self::MD5 => new MD5(),
                self::PHPASS => new PHPass(),
            ];
        }

        $this->algorithms = $algorithms;
    }

    /**
     * Add a new hashing algorithm
     *
     * @param  string  $name
     * @param  Algorithm  $algorithm
     * @return self
     */
    public function addAlgorithm(string $name, Algorithm $algorithm): self
    {
        $this->algorithms[$name] = $algorithm;

        return $this;
    }

    /**
     * Remove a hashing algorithm
     *
     * @param  string  $name
     * @return self
     *
     * @throws \Exception
     */
    public function removeAlgorithm(string $name): self
    {
        if (! isset($this->algorithms[$name])) {
            throw new \Exception("Algorithm '{$name}' not found");
        }

        if ($this->algorithm === $this->algorithms[$name]) {
            throw new \Exception('Cannot remove current algorithm');
        }

        unset($this->algorithms[$name]);

        return $this;
    }

    /**
     * Get a specific hashing algorithm by name
     *
     * @param  string  $name
     * @return Algorithm
     *
     * @throws \Exception
     */
    public function getAlgorithmByName(string $name): Algorithm
    {
        if (! isset($this->algorithms[$name])) {
            throw new \Exception("Algorithm '{$name}' not found");
        }

        return $this->algorithms[$name];
    }

    /**
     * {@inheritdoc}
     */
    public function generate(string $input): string
    {
        return $input; // For passwords, we just return the input as is
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $proof): string
    {
        return $this->algorithm->hash($proof);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $proof, string $hash): bool
    {
        return $this->algorithm->verify($proof, $hash);
    }
}
