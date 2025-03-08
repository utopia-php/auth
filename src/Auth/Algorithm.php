<?php

namespace Utopia\Auth;

abstract class Algorithm
{
    /**
     * @var array $options Algorithm-specific options
     */
    protected array $options = [];

    /**
     * Set algorithm options
     *
     * @param array $options Algorithm-specific options
     * @return self
     */
    protected function setOption(string $key, mixed $value): self
    {
        $this->options[$key] = $value;
        return $this;
    }

    /**
     * Get a specific option value
     *
     * @param string $key The option key to retrieve
     * @param mixed $default Default value if option doesn't exist
     * @return mixed The option value or default if not found
     */
    protected function getOption(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    /**
     * Get algorithm options
     *
     * @return array Algorithm-specific options
     */
    protected function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Hash a value
     *
     * @param string $value
     * @return string
     */
    abstract public function hash(string $value): string;

    /**
     * Verify a value against a hash
     *
     * @param string $value
     * @param string $hash
     * @return bool
     */
    abstract public function verify(string $value, string $hash): bool;
} 