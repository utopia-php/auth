<?php

namespace Utopia\Auth\Hashes;

use Utopia\Auth\Hash;

class Plaintext extends Hash
{
    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'plaintext';
    }
}
