<?php

namespace Utopia\Tests\Auth\OAuth2;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\OAuth2\ResourceIndicators;

class ResourceIndicatorsTest extends TestCase
{
    public function testEmptyValueNormalizesToEmptyArray(): void
    {
        $this->assertSame([], ResourceIndicators::normalize(null));
        $this->assertSame([], ResourceIndicators::normalize(''));
    }

    public function testStringNormalizesToArray(): void
    {
        $this->assertSame(['https://api.example.com/'], ResourceIndicators::normalize('https://api.example.com/'));
    }

    public function testArrayIsNormalizedAndDeduplicated(): void
    {
        $this->assertSame(
            ['https://api.example.com/', 'urn:example:resource'],
            ResourceIndicators::normalize([
                'https://api.example.com/',
                'urn:example:resource',
                'https://api.example.com/',
            ])
        );
    }

    public function testFragmentIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be an absolute URI without a fragment.');

        ResourceIndicators::normalize('https://api.example.com/#section');
    }

    public function testRelativeUriIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be an absolute URI without a fragment.');

        ResourceIndicators::normalize('/relative');
    }

    public function testNonStringIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be a non-empty absolute URI.');

        ResourceIndicators::normalize(['https://api.example.com/', 42]);
    }

    public function testSubset(): void
    {
        $this->assertTrue(ResourceIndicators::isSubset(['https://api.example.com/'], ['https://api.example.com/', 'https://files.example.com/']));
        $this->assertFalse(ResourceIndicators::isSubset(['https://api.example.com/'], ['https://files.example.com/']));
    }

    public function testSameSetIgnoresOrder(): void
    {
        $this->assertTrue(ResourceIndicators::sameSet(
            ['https://api.example.com/', 'https://files.example.com/'],
            ['https://files.example.com/', 'https://api.example.com/']
        ));
    }

    public function testAudienceUsesDefaultWhenNoResourcesRequested(): void
    {
        $this->assertSame('https://cloud.appwrite.io/v1/project1', ResourceIndicators::audience('https://cloud.appwrite.io/v1/project1', []));
    }

    public function testAudiencePrependsDefaultAndDeduplicatesIt(): void
    {
        $this->assertSame(
            ['https://cloud.appwrite.io/v1/project1', 'https://mcp.example.com/'],
            ResourceIndicators::audience('https://cloud.appwrite.io/v1/project1', [
                'https://mcp.example.com/',
                'https://cloud.appwrite.io/v1/project1',
            ])
        );
    }
}
