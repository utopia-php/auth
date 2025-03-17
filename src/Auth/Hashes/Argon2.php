<?php

namespace Utopia\Auth\Hashes;

use Utopia\Auth\Hash;

class Argon2 extends Hash
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->setOption('memoryCost', 65536);
        $this->setOption('timeCost', 4);
        $this->setOption('threads', 3);
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        return \password_hash($value, PASSWORD_ARGON2ID, $this->getOptions());
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return \password_verify($value, $hash);
    }

    /**
     * Set memory cost
     *
     * @param  int  $cost Memory cost in KiB
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setMemoryCost(int $cost): self
    {
        $this->setOption('memoryCost', $cost);

        return $this;
    }

    /**
     * Set time cost
     *
     * @param  int  $cost Number of iterations
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setTimeCost(int $cost): self
    {
        $this->setOption('timeCost', $cost);

        return $this;
    }

    /**
     * Set number of threads
     *
     * @param  int  $threads Number of threads to use
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setThreads(int $threads): self
    {
        $this->setOption('threads', $threads);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'argon2';
    }
}
