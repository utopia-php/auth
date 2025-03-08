<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Algorithm;
use Utopia\Auth\Proof;
use Utopia\Auth\Algorithms\Argon2;
use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Algorithms\MD5;
use Utopia\Auth\Algorithms\PHPass;
use Utopia\Auth\Algorithms\Scrypt;
use Utopia\Auth\Algorithms\ScryptModified;
use Utopia\Auth\Algorithms\Sha;

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
     * @var string
     */
    protected string $default;

    /**
     * @param string $defaultAlgorithm
     * @param array<string, Algorithm> $algorithms
     * 
     * @throws \Exception
     */
    public function __construct(string $default = 'argon2', array $algorithms = [])
    {
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
        
        if (!isset($this->algorithms[$default])) {
            throw new \Exception("Default algorithm '{$default}' not found in provided algorithms");
        }

        $this->default = $default;
    }

    /**
     * Add a new hashing algorithm
     *
     * @param string $name
     * @param Algorithm $algorithm
     * @return self
     */
    public function addAlgorithm(string $name, Algorithm $algorithm): self
    {
        $this->algorithms[$name] = $algorithm;
        return $this;
    }

    /**
     * Set default algorithm
     *
     * @param string $name
     * @return self
     * @throws \Exception
     */
    public function setDefaultAlgorithm(string $name): self
    {
        if (!isset($this->algorithms[$name])) {
            throw new \Exception("Algorithm '{$name}' not found");
        }

        $this->default = $name;
        return $this;
    }

    /**
     * Remove a hashing algorithm
     *
     * @param string $name
     * @return self
     * @throws \Exception
     */
    public function removeAlgorithm(string $name): self
    {
        if (!isset($this->algorithms[$name])) {
            throw new \Exception("Algorithm '{$name}' not found");
        }

        if ($name === $this->default) {
            throw new \Exception("Cannot remove default algorithm");
        }

        unset($this->algorithms[$name]);
        return $this;
    }

    /**
     * Get a hashing algorithm
     *
     * @param string $name
     * @return Algorithm
     * @throws \Exception
     */
    public function getAlgorithm(string $name): Algorithm
    {
        if (!isset($this->algorithms[$name])) {
            throw new \Exception("Algorithm '{$name}' not found");
        }

        return $this->algorithms[$name];
    }

    /**
     * @inheritdoc
     */
    public function generate(string $input): string
    {
        return $input; // For passwords, we just return the input as is
    }

    /**
     * @inheritdoc
     */
    public function hash(string $proof): string
    {
        if (!isset($this->algorithms[$this->default])) {
            throw new \Exception("No algorithms configured");
        }

        return $this->algorithms[$this->default]->hash($proof);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $proof, string $hash): bool
    {
        if (!isset($this->algorithms[$this->default])) {
            throw new \Exception("No algorithms configured");
        }

        return $this->algorithms[$this->default]->verify($proof, $hash);
    }
} 