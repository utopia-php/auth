# Utopia Auth

[![Build Status](https://travis-ci.org/utopia-php/auth.svg?branch=master)](https://travis-ci.org/utopia-php/auth)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/auth.svg)
[![Discord](https://img.shields.io/discord/564160730845151244?label=discord)](https://appwrite.io/discord)

Utopia Auth library is a simple and lite library for handling authentication and authorization in PHP applications. This library provides a collection of secure hashing algorithms and authentication proofs for building robust authentication systems. This library is maintained by the [Appwrite team](https://appwrite.io).

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free and can be used as standalone with any other PHP project or framework.

## Getting Started

Install using composer:
```bash
composer require utopia-php/auth
```

## System Requirements

Utopia Framework requires PHP 8.0 or later. We recommend using the latest PHP version whenever possible.

## Features

### Supported Hashing Algorithms

- **Argon2** - Modern, secure, and recommended password hashing algorithm
- **Bcrypt** - Well-established and secure password hashing
- **Scrypt** - Memory-hard password hashing algorithm
- **ScryptModified** - Modified version of Scrypt with additional features
- **SHA** - Various SHA hash implementations
- **PHPass** - Portable password hashing framework
- **MD5** (Not recommended for passwords, legacy support only)

## Usage

### Password Hashing

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Utopia\Auth\Proofs\Password;
use Utopia\Auth\Algorithms\Argon2;
use Utopia\Auth\Algorithms\Bcrypt;

// Initialize password authentication with default algorithms
$password = new Password();

// Hash a password (uses Argon2 by default)
$hash = $password->hash('user-password');

// Verify the password
$isValid = $password->verify('user-password', $hash);

// Use a specific algorithm with custom parameters
$bcrypt = new Bcrypt();
$bcrypt->setCost(12); // Increase cost factor for better security

$password->setAlgorithm($bcrypt);
$hash = $password->hash('user-password');
```

### Authentication Tokens

```php
<?php

use Utopia\Auth\Proofs\Token;

// Generate secure authentication tokens
$token = new Token(32); // 32 characters length
$authToken = $token->generate(); // Random token
$hashedToken = $token->hash($authToken); // Store this in database

// Later, verify the token
$isValid = $token->verify($authToken, $hashedToken);
```

### One-Time Codes

```php
<?php

use Utopia\Auth\Proofs\Code;

// Generate verification codes (e.g., for 2FA)
$code = new Code(6); // 6-digit code
$verificationCode = $code->generate();
$hashedCode = $code->hash($verificationCode);

// Verify the code
$isValid = $code->verify($verificationCode, $hashedCode);
```

### Human-Readable Phrases

```php
<?php

use Utopia\Auth\Proofs\Phrase;

// Generate memorable authentication phrases
$phrase = new Phrase();
$authPhrase = $phrase->generate(); // e.g., "Brave cat"
$hashedPhrase = $phrase->hash($authPhrase);

// Verify the phrase
$isValid = $phrase->verify($authPhrase, $hashedPhrase);
```

### Advanced Algorithm Configuration

```php
<?php

use Utopia\Auth\Algorithms\Scrypt;
use Utopia\Auth\Algorithms\Argon2;

// Configure Scrypt parameters
$scrypt = new Scrypt();
$scrypt
    ->setCpuCost(16)      // CPU/Memory cost parameter
    ->setMemoryCost(14)   // Memory cost parameter
    ->setParallelCost(2)  // Parallelization parameter
    ->setLength(64)       // Output length in bytes
    ->setSalt('randomsalt123'); // Custom salt

// Configure Argon2 parameters
$argon2 = new Argon2();
$argon2
    ->setMemoryCost(65536)  // Memory cost in KiB
    ->setTimeCost(4)        // Number of iterations
    ->setThreads(3);        // Number of threads
```

## Tests

To run all unit tests, use the following Docker command:

```bash
docker compose exec tests vendor/bin/phpunit --configuration phpunit.xml tests
```

To run static code analysis, use the following Psalm command:

```bash
docker compose exec tests vendor/bin/psalm --show-info=true
```

## Security

We take security seriously. If you discover any security-related issues, please email security@appwrite.io instead of using the issue tracker.

## Contributing

All code contributions - including those of people having commit access - must go through a pull request and be approved by a core developer before being merged. This is to ensure a proper review of all the code.

We truly ❤️ pull requests! If you wish to help, you can learn more about how you can contribute to this project in the [contribution guide](CONTRIBUTING.md).

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php) 