<?php

namespace Utopia\Auth;

class Store
{
    /**
     * @var array<string, mixed>
     */
    protected array $data = [];

    /**
     * Get a value from the store
     *
     * @param  string  $key
     * @param  mixed  $default
     * @return mixed
     */
    public function get(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * Set a value in the store
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return self
     */
    public function set(string $key, mixed $value): self
    {
        $this->data[$key] = $value;

        return $this;
    }

    /**
     * Encode store data to base64 string
     *
     * @return string
     *
     * @throws \JsonException
     */
    public function encode(): string
    {
        $json = json_encode($this->data, JSON_THROW_ON_ERROR);

        return base64_encode($json);
    }

    /**
     * Decode base64 string and populate current store instance
     *
     * @param  string  $data
     * @return self
     */
    public function decode(string $data): self
    {
        try {
            $decoded = base64_decode($data, true);
            if ($decoded === false) {
                return $this;
            }

            $json = json_decode($decoded, true, 512, JSON_THROW_ON_ERROR);
            if (is_array($json)) {
                foreach ($json as $key => $value) {
                    $this->set($key, $value);
                }
            }
        } catch (\JsonException $e) {
            // Invalid JSON, return empty store
        }

        return $this;
    }
}
