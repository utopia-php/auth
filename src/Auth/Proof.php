<?php

namespace Utopia\Auth;

use Utopia\Auth\Hashes\Argon2;

abstract class Proof
{
    /**
     * @var Hash
     */
    protected Hash $hash;

    public function __construct()
    {
        $this->hash = new Argon2();
    }

    /**
     * Set custom hash
     *
     * @param  Hash  $hash
     * @return self
     */
    public function setHash(Hash $hash): self
    {
        $this->hash = $hash;

        return $this;
    }

    /**
     * Get current hash
     *
     * @return Hash
     */
    public function getHash(): Hash
    {
        return $this->hash;
    }

    /**
     * Generate a proof
     *
     * @return string
     */
    abstract public function generate(): string;

    /**
     * Hash a proof
     *
     * @param  string  $proof
     * @return string
     */
    public function hash(string $proof): string
    {
        return $this->hash->hash($proof);
    }

    /**
     * Verify a proof
     *
     * @param  string  $proof
     * @param  string  $hash
     * @return bool
     */
    public function verify(string $proof, string $hash): bool
    {
        return $this->hash->verify($proof, $hash);
    }
}
