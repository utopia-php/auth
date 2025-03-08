# Utopia Auth

[![Build Status](https://travis-ci.org/utopia-php/auth.svg?branch=master)](https://travis-ci.org/utopia-php/auth)
![Total Downloads](https://img.shields.io/packagist/dt/utopia-php/auth.svg)
[![Discord](https://img.shields.io/discord/564160730845151244?label=discord)](https://appwrite.io/discord)

Utopia Auth library is a simple and lite library for handling authentication and authorization in PHP applications. This library is aiming to be as simple and easy to learn and use. This library is maintained by the [Appwrite team](https://appwrite.io).

Although this library is part of the [Utopia Framework](https://github.com/utopia-php/framework) project it is dependency free and can be used as standalone with any other PHP project or framework.

## Getting Started

Install using composer:
```bash
composer require utopia-php/auth
```

## System Requirements

Utopia Framework requires PHP 8.0 or later. We recommend using the latest PHP version whenever possible.

## Usage

Sample usage of the library:

```php
<?php

require_once __DIR__ . '/vendor/autoload.php';

use Utopia\Auth\Auth;

// Initialize Auth
$auth = new Auth();

// Add your authentication logic here
```

## Tests

To run all unit tests, use the following Docker command:

```bash
docker compose exec tests vendor/bin/phpunit --configuration phpunit.xml tests
```

To run static code analysis, use the following Psalm command:

```bash
docker-compose exec php8 vendor/bin/psalm --show-info=true
```

## Contributing

All code contributions - including those of people having commit access - must go through a pull request and be approved by a core developer before being merged. This is to ensure a proper review of all the code.

We truly ❤️ pull requests! If you wish to help, you can learn more about how you can contribute to this project in the [contribution guide](CONTRIBUTING.md).

## Copyright and license

The MIT License (MIT) [http://www.opensource.org/licenses/mit-license.php](http://www.opensource.org/licenses/mit-license.php) 