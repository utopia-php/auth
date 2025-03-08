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

### Basic Usage

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Utopia\Auth\Algorithm;
use Utopia\Auth\Algorithms\Argon2;

// Initialize with a specific algorithm
$algorithm = new Argon2();

// Hash a password
$hash = $algorithm->hash('user-password');

// Verify a password
$isValid = $algorithm->verify('user-password', $hash);
```

### Using Different Algorithms

```php
<?php

use Utopia\Auth\Algorithms\Bcrypt;
use Utopia\Auth\Algorithms\Scrypt;

// Using Bcrypt
$bcrypt = new Bcrypt();
$hash = $bcrypt->hash('password');

// Using Scrypt
$scrypt = new Scrypt();
$hash = $scrypt->hash('password');
```

### Authentication Proofs

The library also supports various authentication proofs for implementing secure authentication flows:

```php
<?php

use Utopia\Auth\Proofs;

// Initialize proofs
$proofs = new Proofs();

// Add your authentication proof logic here
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