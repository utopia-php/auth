<?php

namespace Utopia\Auth\Algorithms;

use Utopia\Auth\Algorithm;

class Sha extends Algorithm
{
    public const SHA1 = 'sha1';
    public const SHA224 = 'sha224';
    public const SHA256 = 'sha256';
    public const SHA384 = 'sha384';
    public const SHA512 = 'sha512';
    public const SHA3_224 = 'sha3-224';
    public const SHA3_256 = 'sha3-256';
    public const SHA3_384 = 'sha3-384';
    public const SHA3_512 = 'sha3-512';

    /**
     * Constructor
     */
    public function __construct()
    {
        $this->setOption('version', 'sha3-512');
    }

    /**
     * Valid SHA versions
     */
    private const VALID_VERSIONS = [
        'sha1',
        'sha224',
        'sha256',
        'sha384',
        'sha512',
        'sha3-224',
        'sha3-256',
        'sha3-384',
        'sha3-512'
    ];

    /**
     * Set SHA version
     * 
     * @param string $version SHA version to use
     * @return self
     * @throws \InvalidArgumentException
     */
    public function setVersion(string $version): self
    {
        if (!in_array($version, self::VALID_VERSIONS, true)) {
            throw new \InvalidArgumentException('Invalid SHA version. Valid versions are: ' . implode(', ', self::VALID_VERSIONS));
        }
        
        return $this->setOption('version', $version);
    }

    /**
     * @inheritdoc
     */
    public function hash(string $value): string
    {
        return \hash($this->getOption('version'), $value);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $value, string $hash): bool
    {
        return $this->hash($value) === $hash;
    }
} 