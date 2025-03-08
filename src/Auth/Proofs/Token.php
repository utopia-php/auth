<?php

namespace Utopia\Auth\Proofs;

use Utopia\Auth\Proof;

class Token extends Proof
{
    /**
     * @var int
     */
    protected int $length;

    /**
     * @param int $length
     * @throws \Exception
     */
    public function __construct(int $length = 256)
    {
        if ($length <= 0) {
            throw new \Exception('Token length must be greater than 0');
        }
        
        $this->length = $length;
    }

    /**
     * @inheritdoc
     */
    public function generate(string $input): string
    {
        $bytesLength = (int) ceil($this->length / 2);
        $token = \bin2hex(\random_bytes($bytesLength));

        return substr($token, 0, $this->length);
    }

    /**
     * @inheritdoc
     */
    public function hash(string $proof): string
    {
        return \hash('sha256', $proof);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $proof, string $hash): bool
    {
        return $this->hash($proof) === $hash;
    }
} 