<?php

namespace Utopia\Auth;

abstract class Proof
{
    /**
     * Generate a proof
     * 
     * @param string $input
     * @return string
     */
    abstract public function generate(string $input): string;

    /**
     * Hash a proof
     * 
     * @param string $proof
     * @return string
     */
    abstract public function hash(string $proof): string;

    /**
     * Verify a proof
     * 
     * @param string $proof
     * @param string $hash
     * @return bool
     */
    abstract public function verify(string $proof, string $hash): bool;
} 