<?php

namespace Utopia\Auth\Algorithms;

use Utopia\Auth\Algorithm;

class MD5 extends Algorithm
{
    /**
     * @inheritdoc
     */
    public function hash(string $value): string
    {
        return \md5($value);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }
} 