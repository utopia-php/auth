<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Proof;

class Code extends Proof
{
    /**
     * @var int
     */
    protected int $length;

    /**
     * @param  int  $length
     *
     * @throws \Exception
     */
    public function __construct(int $length = 6)
    {
        if ($length <= 0) {
            throw new \Exception('Code length must be greater than 0');
        }

        $this->length = $length;
    }

    /**
     * {@inheritdoc}
     */
    public function generate(string $input): string
    {
        $value = '';

        for ($i = 0; $i < $this->length; $i++) {
            $value .= random_int(0, 9);
        }

        return $value;
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $proof): string
    {
        return \hash('sha256', $proof);
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $proof, string $hash): bool
    {
        return $this->hash($proof) === $hash;
    }
}
