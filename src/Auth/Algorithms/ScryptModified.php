<?php

namespace Utopia\Auth\Algorithms;

use Utopia\Auth\Algorithm;

class ScryptModified extends Algorithm
{
    /**
     * Constructor to initialize with secure default options
     */
    public function __construct()
    {
        // Generate cryptographically secure random values
        $salt = random_bytes(16);
        $saltSeparator = random_bytes(16);
        $signerKey = random_bytes(32);

        // Set default options with secure random values
        $this->setOption('salt', base64_encode($salt));
        $this->setOption('saltSeparator', base64_encode($saltSeparator));
        $this->setOption('signerKey', base64_encode($signerKey));
    }

    /**
     * {@inheritdoc}
     */
    public function hash(string $value): string
    {
        $options = $this->getOptions();
        $derivedKeyBytes = $this->generateDerivedKey($value);
        $signerKeyBytes = \base64_decode($options['signerKey']);

        return \base64_encode($this->hashKeys($signerKeyBytes, $derivedKeyBytes));
    }

    /**
     * {@inheritdoc}
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }

    /**
     * Generate derived key using scrypt
     */
    private function generateDerivedKey(string $value): string
    {
        $options = $this->getOptions();
        $saltBytes = \base64_decode($options['salt']);
        $saltSeparatorBytes = \base64_decode($options['saltSeparator']);

        $value = \mb_convert_encoding($value, 'UTF-8');
        $derivedKey = \scrypt($value, $saltBytes.$saltSeparatorBytes, 16384, 8, 1, 64);

        return \hex2bin($derivedKey);
    }

    /**
     * Hash keys using AES-256-CTR
     */
    private function hashKeys(string $signerKeyBytes, string $derivedKeyBytes): string
    {
        $key = \substr($derivedKeyBytes, 0, 32);
        $iv = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";

        return \openssl_encrypt($signerKeyBytes, 'aes-256-ctr', $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * Set salt value
     *
     * @param  string  $salt Base64 encoded salt value
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setSalt(string $salt): self
    {
        if (empty($salt)) {
            throw new \InvalidArgumentException('Salt cannot be empty');
        }

        if (! preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $salt)) {
            throw new \InvalidArgumentException('Salt must be base64 encoded');
        }

        return $this->setOption('salt', $salt);
    }

    /**
     * Set salt separator
     *
     * @param  string  $separator Base64 encoded salt separator
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setSaltSeparator(string $separator): self
    {
        if (! preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $separator)) {
            throw new \InvalidArgumentException('Salt separator must be base64 encoded');
        }

        return $this->setOption('saltSeparator', $separator);
    }

    /**
     * Set signer key
     *
     * @param  string  $key Base64 encoded signer key
     * @return self
     *
     * @throws \InvalidArgumentException
     */
    public function setSignerKey(string $key): self
    {
        if (empty($key)) {
            throw new \InvalidArgumentException('Signer key cannot be empty');
        }

        if (! preg_match('/^[A-Za-z0-9+\/]+={0,2}$/', $key)) {
            throw new \InvalidArgumentException('Signer key must be base64 encoded');
        }

        return $this->setOption('signerKey', $key);
    }
}
