<?php

namespace Utopia\Auth;

class OIDC
{
    /**
     * PEM-encoded RSA private key used to sign id_tokens.
     */
    protected string $privateKey;

    /**
     * PEM-encoded RSA public key matching the private key. Used to derive
     * the key id (kid) and to expose the public JWK for verification.
     */
    protected string $publicKey;

    /**
     * The token issuer (the "iss" claim). For OIDC this is the URL of the
     * authorization server, e.g. "https://example.com/v1/oauth2/<id>".
     */
    protected string $issuer;

    /**
     * The JWS "kid" header. When null it is derived from the public key.
     */
    protected ?string $keyId;

    /**
     * @param  string  $privateKey  PEM-encoded RSA private key, generate using {@see generateKeyPair()}.
     * @param  string  $publicKey  PEM-encoded RSA public key, generate using {@see generatePublicKey()}.
     * @param  string  $issuer  The "iss" claim value.
     * @param  string|null  $keyId  Optional "kid" header; derived from the public key when null.
     *
     * @throws \Exception When a key cannot be parsed.
     */
    public function __construct(
        string $privateKey,
        string $publicKey,
        string $issuer,
        ?string $keyId = null,
    ) {
        if (empty($privateKey) || empty($publicKey)) {
            throw new \Exception('Both a private and a public key are required');
        }

        if (empty($issuer)) {
            throw new \Exception('An issuer is required');
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
        $this->issuer = $issuer;
        $this->keyId = $keyId;
    }

    /**
     * Generate a fresh RSA keypair suitable for signing id_tokens with RS256.
     *
     * Returns a tuple of PEM-encoded keys that can be passed straight to the
     * constructor: [$privateKey, $publicKey].
     *
     * @return array{0: string, 1: string}
     *
     * @throws \Exception When key generation fails.
     */
    public static function generateKeyPair(int $bits = 2048): array
    {
        $resource = \openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new \Exception('Unable to generate an RSA key pair');
        }

        return [
            self::generatePrivateKey($resource),
            self::generatePublicKey($resource),
        ];
    }

    /**
     * Export the PEM-encoded private key from an OpenSSL key resource, or
     * generate a fresh keypair and return its private key when none is given.
     *
     * @param  \OpenSSLAsymmetricKey|null  $resource  An existing key resource, or null to create one.
     *
     * @throws \Exception When the key cannot be exported.
     */
    private static function generatePrivateKey(?\OpenSSLAsymmetricKey $resource = null, int $bits = 2048): string
    {
        $resource ??= \openssl_pkey_new([
            'private_key_bits' => $bits,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($resource === false) {
            throw new \Exception('Unable to generate an RSA key pair');
        }

        $privateKey = '';
        if (!\openssl_pkey_export($resource, $privateKey)) {
            throw new \Exception('Unable to export the private key');
        }

        return $privateKey;
    }

    /**
     * Export the PEM-encoded public key, either from an existing OpenSSL key
     * resource or from a PEM-encoded private key string.
     *
     * @param  \OpenSSLAsymmetricKey|string  $key  A key resource or a PEM-encoded private key.
     *
     * @throws \Exception When the public key cannot be derived.
     */
    private static function generatePublicKey(\OpenSSLAsymmetricKey|string $key): string
    {
        if (\is_string($key)) {
            $resource = \openssl_pkey_get_private($key);
            if ($resource === false) {
                throw new \Exception('Unable to parse the private key');
            }
        } else {
            $resource = $key;
        }

        $details = \openssl_pkey_get_details($resource);
        if ($details === false || !isset($details['key'])) {
            throw new \Exception('Unable to export the public key');
        }

        return $details['key'];
    }

    /**
     * Build a signed OIDC id_token (OpenID Connect Core 1.0 §2).
     *
     * Pass $accessToken when an access_token is co-issued in the same
     * response (OIDC §3.1.3.6 — adds at_hash). Pass $code when an authorization
     * code is co-issued in the same response (OIDC §3.3.2.11, Hybrid Flow —
     * adds c_hash). Either, neither, or both may be set.
     *
     * Signs with RS256 using the configured RSA private key.
     *
     * @param  string  $subject  The "sub" claim (the authenticated user).
     * @param  string  $audience  The "aud" claim (the client the token is for).
     * @param  int  $authTime  Time the end-user authenticated ("auth_time"), as a Unix timestamp.
     * @param  int  $duration  Lifetime of the token in seconds (used for "exp").
     * @param  string|null  $nonce  The "nonce" value sent in the authentication request.
     * @param  string|null  $accessToken  Co-issued access_token; adds "at_hash" when set.
     * @param  string|null  $code  Co-issued authorization code; adds "c_hash" when set.
     * @param  array<string, mixed>  $claims  Additional claims to merge into the payload.
     *
     * @throws \Exception When signing fails.
     */
    public function issue(
        string $subject,
        string $audience,
        int $authTime,
        int $duration,
        ?string $nonce = null,
        ?string $accessToken = null,
        ?string $code = null,
        array $claims = [],
    ): string {
        $now = \time();

        $claims = \array_merge($claims, [
            'iss' => $this->issuer,
            'sub' => $subject,
            'aud' => $audience,
            'exp' => $now + $duration,
            'iat' => $now,
            'auth_time' => $authTime,
        ]);

        if (!empty($nonce)) {
            $claims['nonce'] = $nonce;
        }

        if (!empty($accessToken)) {
            $claims['at_hash'] = $this->leftHalfHash($accessToken);
        }

        if (!empty($code)) {
            $claims['c_hash'] = $this->leftHalfHash($code);
        }

        $header = [
            'typ' => 'JWT',
            'alg' => 'RS256',
            'kid' => $this->getKeyId(),
        ];

        $signingInput = $this->base64UrlEncode((string) \json_encode($header))
            . '.'
            . $this->base64UrlEncode((string) \json_encode($claims));

        $privateKey = \openssl_pkey_get_private($this->privateKey);
        if ($privateKey === false) {
            throw new \Exception('Unable to parse the private key');
        }

        $signature = '';
        if (!\openssl_sign($signingInput, $signature, $privateKey, OPENSSL_ALGO_SHA256)) {
            throw new \Exception('Unable to sign the id_token');
        }

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }

    /**
     * Get the JWS "kid" header. When none was supplied it is derived
     * deterministically from the public key's RSA modulus, so the same key
     * always yields the same id.
     *
     * @throws \Exception When the public key cannot be parsed.
     */
    public function getKeyId(): string
    {
        if ($this->keyId !== null) {
            return $this->keyId;
        }

        $this->keyId = \hash('sha256', $this->getModulus());

        return $this->keyId;
    }

    /**
     * Build the public key as a JWK (RFC 7517) suitable for publishing on a
     * JWKS endpoint so clients can verify the issued id_tokens.
     *
     * @return array<string, string>
     *
     * @throws \Exception When the public key cannot be parsed.
     */
    public function getPublicJwk(): array
    {
        $publicKey = \openssl_pkey_get_public($this->publicKey);
        if ($publicKey === false) {
            throw new \Exception('Unable to parse the public key');
        }

        $details = \openssl_pkey_get_details($publicKey);
        if ($details === false || !isset($details['rsa'])) {
            throw new \Exception('Public key is not an RSA key');
        }

        return [
            'kty' => 'RSA',
            'use' => 'sig',
            'alg' => 'RS256',
            'kid' => $this->getKeyId(),
            'n' => $this->base64UrlEncode($details['rsa']['n']),
            'e' => $this->base64UrlEncode($details['rsa']['e']),
        ];
    }

    /**
     * Read the raw RSA modulus (the "n" parameter) from the public key.
     *
     * @throws \Exception When the public key cannot be parsed.
     */
    protected function getModulus(): string
    {
        $publicKey = \openssl_pkey_get_public($this->publicKey);
        if ($publicKey === false) {
            throw new \Exception('Unable to parse the public key');
        }

        $details = \openssl_pkey_get_details($publicKey);
        if ($details === false || !isset($details['rsa']['n'])) {
            throw new \Exception('Public key is not an RSA key');
        }

        return $details['rsa']['n'];
    }

    /**
     * OIDC §3.1.3.6 / §3.3.2.11: hash with the same algorithm family as the
     * id_token signature (SHA-256 for RS256), take the left-most half
     * (16 bytes / 128 bits), base64url-encode without padding.
     */
    protected function leftHalfHash(string $value): string
    {
        return $this->base64UrlEncode(\substr(\hash('sha256', $value, true), 0, 16));
    }

    /**
     * Base64url-encode without padding (RFC 7515 §2).
     */
    protected function base64UrlEncode(string $value): string
    {
        return \rtrim(\strtr(\base64_encode($value), '+/', '-_'), '=');
    }
}
