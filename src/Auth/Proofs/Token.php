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
     * @param  int  $length
     *
     * @throws \Exception
     */
    public function __construct(int $length = 256)
    {
        parent::__construct();

        if ($length <= 0) {
            throw new \Exception('Token length must be greater than 0');
        }

        $this->length = $length;
    }

    /**
     * {@inheritdoc}
     */
    public function generate(): string
    {
        $bytesLength = max(1, (int) ceil($this->length / 2));
        $token = \bin2hex(\random_bytes($bytesLength));

        return substr($token, 0, $this->length);
    }

    /**
     * Get the token length
     *
     * @return int
     */
    public function getLength(): int
    {
        return $this->length;
    }

    /**
     * Set the token length
     *
     * @param  int  $length
     * @return self
     *
     * @throws \Exception
     */
    public function setLength(int $length): self
    {
        if ($length <= 0) {
            throw new \Exception('Token length must be greater than 0');
        }

        $this->length = $length;

        return $this;
    }
}
