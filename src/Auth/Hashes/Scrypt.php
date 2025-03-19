<?php

namespace Utopia\Auth\Hashes;

use Utopia\Auth\Hash;

class Scrypt extends Hash
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->setOption('type', $this->getName());
        $this->setOption('costCpu', 8);
        $this->setOption('costMemory', 14);
        $this->setOption('costParallel', 1);
        $this->setOption('length', 64);
        $this->setOption('salt', '');
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        if (! function_exists('scrypt')) {
            throw new \RuntimeException('The scrypt extension is required. Please install php-scrypt.');
        }

        return \scrypt(
            $value,
            $this->getOption('salt'),
            $this->getOption('costCpu'),
            $this->getOption('costMemory'),
            $this->getOption('costParallel'),
            $this->getOption('length')
        );
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }

    /**
     * Set CPU cost parameter
     *
     * @param  int  $cost CPU cost parameter N. Must be larger than 1 and a power of 2
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setCpuCost(int $cost): self
    {
        if ($cost <= 1 || ($cost & ($cost - 1)) !== 0) {
            throw new \InvalidArgumentException('CPU cost must be > 1 and a power of 2');
        }

        $this->setOption('costCpu', $cost);

        return $this;
    }

    /**
     * Set memory cost parameter
     *
     * @param  int  $cost Memory cost parameter r
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setMemoryCost(int $cost): self
    {
        if ($cost < 1) {
            throw new \InvalidArgumentException('Memory cost must be >= 1');
        }

        $this->setOption('costMemory', $cost);

        return $this;
    }

    /**
     * Set parallelization parameter
     *
     * @param  int  $cost Parallelization parameter p
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setParallelCost(int $cost): self
    {
        if ($cost < 1) {
            throw new \InvalidArgumentException('Parallel cost must be >= 1');
        }

        $this->setOption('costParallel', $cost);

        return $this;
    }

    /**
     * Set output length
     *
     * @param  int  $length Desired output length in bytes
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setLength(int $length): self
    {
        if ($length < 16) {
            throw new \InvalidArgumentException('Length must be >= 16 bytes');
        }

        $this->setOption('length', $length);

        return $this;
    }

    /**
     * Set salt value
     *
     * @param  string  $salt Salt value for the hash
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setSalt(string $salt): self
    {
        if (empty($salt)) {
            throw new \InvalidArgumentException('Salt cannot be empty');
        }

        $this->setOption('salt', $salt);

        return $this;
    }

    /**
     * {@inheritdoc}
     */
    public function getName(): string
    {
        return 'scrypt';
    }
}
