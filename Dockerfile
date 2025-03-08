FROM composer:2.0 as composer

ARG TESTING=false
ENV TESTING=$TESTING

WORKDIR /usr/local/src/
COPY composer.lock /usr/local/src/
COPY composer.json /usr/local/src/

RUN composer update \
    --ignore-platform-reqs \
    --optimize-autoloader \
    --no-plugins \
    --no-scripts \
    --prefer-dist

FROM php:8.0-cli-alpine as compile

RUN apk add --no-cache \
    git \
    autoconf \
    make \
    g++ \
    libsodium-dev

# Build scrypt extension
FROM compile AS scrypt
RUN pecl install scrypt

FROM compile as final

LABEL maintainer="team@appwrite.io"

WORKDIR /usr/src/code

# Enable hash extension (built-in)
# Install and enable sodium extension
RUN docker-php-ext-install sodium

# Copy and enable scrypt extension
COPY --from=scrypt /usr/local/lib/php/extensions/no-debug-non-zts-20200930/scrypt.so /usr/local/lib/php/extensions/no-debug-non-zts-20200930/
RUN docker-php-ext-enable scrypt

# Configure PHP
RUN mv "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
    && echo "memory_limit=256M" >> $PHP_INI_DIR/php.ini

# Copy composer dependencies
COPY --from=composer /usr/local/src/vendor /usr/src/code/vendor

# Add Source Code
COPY . /usr/src/code

CMD [ "tail", "-f", "/dev/null" ]