<?php

namespace Utopia\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Auth;

class AuthTest extends TestCase
{
    protected ?Auth $auth = null;

    protected function setUp(): void
    {
        $this->auth = new Auth([
            'secret' => 'test-secret',
        ]);
    }

    public function testCreateToken(): void
    {
        $payload = ['user_id' => 1, 'email' => 'test@example.com'];
        $token = $this->auth->createToken($payload);
        
        $this->assertIsString($token);
        $this->assertNotEmpty($token);
    }

    public function testVerifyToken(): void
    {
        $payload = ['user_id' => 1, 'email' => 'test@example.com'];
        $token = $this->auth->createToken($payload);
        
        $this->assertTrue($this->auth->verifyToken($token));
    }

    public function testGetPayload(): void
    {
        $payload = ['user_id' => 1, 'email' => 'test@example.com'];
        $token = $this->auth->createToken($payload);
        
        $extractedPayload = $this->auth->getPayload($token);
        $this->assertEquals($payload, $extractedPayload);
    }
} 