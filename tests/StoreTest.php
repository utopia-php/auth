<?php

namespace Utopia\Auth\Tests;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\Store;

class StoreTest extends TestCase
{
    public function testGetAndSet(): void
    {
        $store = new Store();

        // Test setting and getting a string
        $store->set('name', 'John Doe');
        $this->assertEquals('John Doe', $store->get('name'));

        // Test setting and getting different types
        $store->set('age', 30)
              ->set('active', true)
              ->set('scores', [95, 87, 92])
              ->set('details', ['city' => 'New York', 'country' => 'USA']);

        $this->assertEquals(30, $store->get('age'));
        $this->assertTrue($store->get('active'));
        $this->assertEquals([95, 87, 92], $store->get('scores'));
        $this->assertEquals(['city' => 'New York', 'country' => 'USA'], $store->get('details'));

        // Test default value for non-existent key
        $this->assertNull($store->get('nonexistent'));
        $this->assertEquals('default', $store->get('nonexistent', 'default'));
    }

    public function testEncodeAndDecode(): void
    {
        $store = new Store();
        $data = [
            'name' => 'John Doe',
            'age' => 30,
            'active' => true,
            'scores' => [95, 87, 92],
            'details' => ['city' => 'New York', 'country' => 'USA'],
        ];

        // Set multiple values
        foreach ($data as $key => $value) {
            $store->set($key, $value);
        }

        // Encode the store
        $encoded = $store->encode();

        // Verify it's a valid base64 string
        $decoded = base64_decode($encoded, true);
        $this->assertNotFalse($decoded);
        $this->assertEquals($encoded, base64_encode($decoded));

        // Create a new store and decode the data
        $newStore = new Store();
        $newStore->decode($encoded);

        // Verify all data was preserved
        foreach ($data as $key => $value) {
            $this->assertEquals($value, $newStore->get($key));
        }
    }

    public function testDecodeInvalidData(): void
    {
        $store = new Store();

        // Test decoding invalid base64
        $store->decode('invalid-base64');
        $this->assertNull($store->get('any'));

        // Test decoding valid base64 but invalid JSON
        $store->decode(base64_encode('invalid-json'));
        $this->assertNull($store->get('any'));

        // Test decoding valid base64 and JSON, but not an array
        $json = json_encode('string', JSON_THROW_ON_ERROR);
        $store->decode(base64_encode($json));
        $this->assertNull($store->get('any'));
    }

    public function testEncodeWithInvalidData(): void
    {
        $store = new Store();
        // Create an invalid UTF-8 string that will cause json_encode to fail
        $store->set('invalid', "\xFF");

        $this->expectException(\JsonException::class);
        $store->encode();
    }
}
