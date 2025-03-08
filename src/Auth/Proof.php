<?php

namespace Utopia\Auth;

use Utopia\Auth\Algorithms\Argon2;

abstract class Proof
{
    /**
     * @var Algorithm
     */
    protected Algorithm $algorithm;

    public function __construct()
    {
        $this->algorithm = new Argon2();
    }

    /**
     * Set custom algorithm
     *
     * @param  Algorithm  $algorithm
     * @return self
     */
    public function setAlgorithm(Algorithm $algorithm): self
    {
        $this->algorithm = $algorithm;

        return $this;
    }

    /**
     * Get current algorithm
     *
     * @return Algorithm
     */
    public function getAlgorithm(): Algorithm
    {
        return $this->algorithm;
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
    abstract public function hash(string $proof): string;

    /**
     * Verify a proof
     *
     * @param  string  $proof
     * @param  string  $hash
     * @return bool
     */
    abstract public function verify(string $proof, string $hash): bool;
}
