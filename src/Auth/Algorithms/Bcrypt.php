<?php

namespace Utopia\Auth\Algorithms;

use Utopia\Auth\Algorithm;

class Bcrypt extends Algorithm
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->setOption('cost', 8);
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        return \password_hash($value, PASSWORD_BCRYPT, $this->getOptions());
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return \password_verify($value, $hash);
    }

    /**
     * Set cost parameter
     *
     * @param  int  $cost Cost parameter between 4 and 31
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setCost(int $cost): self
    {
        if ($cost < 4 || $cost > 31) {
            throw new \InvalidArgumentException('Cost must be between 4 and 31');
        }

        return $this->setOption('cost', $cost);
    }
}
