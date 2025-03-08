<?php

namespace Utopia\Auth\Algorithms;

use Utopia\Auth\Algorithm;

class Argon2 extends Algorithm
{
    /**
     * Constructor
     */
    public function __construct()
    {
        $this->setOption('memory_cost', 65536);
        $this->setOption('time_cost', 4);
        $this->setOption('threads', 3);
    }

    /**
     * @inheritdoc
     */
    public function hash(string $value): string
    {
        return \password_hash($value, PASSWORD_ARGON2ID, $this->getOptions());
    }

    /**
     * @inheritdoc
     */
    public function verify(string $value, string $hash): bool
    {
        return \password_verify($value, $hash);
    }

    /**
     * Set memory cost
     * 
     * @param int $cost Memory cost in KiB
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setMemoryCost(int $cost): self
    {
        if ($cost < PASSWORD_ARGON2_DEFAULT_MEMORY_COST) {
            throw new \InvalidArgumentException('Memory cost must be >= ' . PASSWORD_ARGON2_DEFAULT_MEMORY_COST . ' KiB');
        }
        
        return $this->setOption('memory_cost', $cost);
    }

    /**
     * Set time cost
     * 
     * @param int $cost Number of iterations
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setTimeCost(int $cost): self
    {
        if ($cost < PASSWORD_ARGON2_DEFAULT_TIME_COST) {
            throw new \InvalidArgumentException('Time cost must be >= ' . PASSWORD_ARGON2_DEFAULT_TIME_COST);
        }
        
        return $this->setOption('time_cost', $cost);
    }

    /**
     * Set number of threads
     * 
     * @param int $threads Number of threads to use
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setThreads(int $threads): self
    {
        if ($threads < PASSWORD_ARGON2_DEFAULT_THREADS) {
            throw new \InvalidArgumentException('Threads must be >= ' . PASSWORD_ARGON2_DEFAULT_THREADS);
        }
        
        return $this->setOption('threads', $threads);
    }
} 