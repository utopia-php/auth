<?php

namespace Utopia\Auth;

class Store
{
    /**
     * @var array<string, mixed>
     */
    protected array $data = [];

    /**
     * @var string|null
     */
    protected ?string $key = null;

    /**
     * Get a property from the store
     *
     * @param  string  $key
     * @param  mixed  $default
     * @return mixed
     */
    public function getProperty(string $key, mixed $default = null): mixed
    {
        return $this->data[$key] ?? $default;
    }

    /**
     * Set a property in the store
     *
     * @param  string  $key
     * @param  mixed  $value
     * @return self
     */
    public function setProperty(string $key, mixed $value): self
    {
        $this->data[$key] = $value;

        return $this;
    }

    /**
     * Get the store key
     *
     * @return string|null
     */
    public function getKey(): ?string
    {
        return $this->key;
    }

    /**
     * Set the store key
     *
     * @param  string|null  $key
     * @return self
     */
    public function setKey(?string $key): self
    {
        $this->key = $key;

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
                    $this->setProperty($key, $value);
                }
            }
        } catch (\JsonException $e) {
            // Invalid JSON, return empty store
        }

        return $this;
    }
}
