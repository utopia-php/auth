<?php

namespace Utopia\Auth;

abstract class Hash
{
    /**
     * @var array<string, mixed> Hash-specific options
     */
    protected array $options = [];

    /**
     * Set hashing options
     *
     * @param  string  $key The option key to set
     * @param  mixed  $value The value to set for the option
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
     * @param  string  $key The option key to retrieve
     * @param  mixed  $default Default value if option doesn't exist
     * @return mixed The option value or default if not found
     */
    protected function getOption(string $key, mixed $default = null): mixed
    {
        return $this->options[$key] ?? $default;
    }

    /**
     * Get hashing options
     *
     * @return array<string, mixed> Hash-specific options
     */
    protected function getOptions(): array
    {
        return $this->options;
    }

    /**
     * Hash a value
     *
     * @param  string  $value
     * @return string
     */
    abstract public function hash(string $value): string;

    /**
     * Verify a value against a hash
     *
     * @param  string  $value
     * @param  string  $hash
     * @return bool
     */
    abstract public function verify(string $value, string $hash): bool;
}
