<?php

namespace Utopia\Auth\Hashes;

use Utopia\Auth\Hash;

class MD5 extends Hash
{
    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        return \md5($value);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }
}
