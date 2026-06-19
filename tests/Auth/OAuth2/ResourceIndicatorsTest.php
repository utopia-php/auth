<?php

namespace Utopia\Tests\Auth\OAuth2;

use PHPUnit\Framework\TestCase;
use Utopia\Auth\OAuth2\ResourceIndicators;

class ResourceIndicatorsTest extends TestCase
{
    public function testEmptyValueNormalizesToEmptyArray(): void
    {
        $this->assertSame([], ResourceIndicators::from(null)->toArray());
        $this->assertSame([], ResourceIndicators::from('')->toArray());
    }

    public function testStringNormalizesToArray(): void
    {
        $this->assertSame(['https://api.example.com/'], ResourceIndicators::from('https://api.example.com/')->toArray());
    }

    public function testArrayIsNormalizedAndDeduplicated(): void
    {
        $this->assertSame(
            ['https://api.example.com/', 'urn:example:resource'],
            ResourceIndicators::from([
                'https://api.example.com/',
                'urn:example:resource',
                'https://api.example.com/',
            ])->toArray()
        );
    }

    public function testFragmentIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be an absolute URI without a fragment.');

        ResourceIndicators::from('https://api.example.com/#section');
    }

    public function testRelativeUriIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be an absolute URI without a fragment.');

        ResourceIndicators::from('/relative');
    }

    public function testNonStringIsRejected(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('resource must be a non-empty absolute URI.');

        ResourceIndicators::from(['https://api.example.com/', 42]);
    }

    public function testSubset(): void
    {
        $this->assertTrue(
            ResourceIndicators::from(['https://api.example.com/'])
                ->isSubsetOf(ResourceIndicators::from(['https://api.example.com/', 'https://files.example.com/']))
        );
        $this->assertFalse(
            ResourceIndicators::from(['https://api.example.com/'])
                ->isSubsetOf(ResourceIndicators::from(['https://files.example.com/']))
        );
    }

    public function testSameSetIgnoresOrder(): void
    {
        $this->assertTrue(
            ResourceIndicators::from(['https://api.example.com/', 'https://files.example.com/'])
                ->equals(ResourceIndicators::from(['https://files.example.com/', 'https://api.example.com/']))
        );
    }

    public function testAudienceUsesDefaultWhenNoResourcesRequested(): void
    {
        $this->assertSame(
            'https://cloud.appwrite.io/v1/project1',
            ResourceIndicators::from(null)->audience('https://cloud.appwrite.io/v1/project1')
        );
    }

    public function testAudiencePrependsDefaultAndDeduplicatesIt(): void
    {
        $this->assertSame(
            ['https://cloud.appwrite.io/v1/project1', 'https://mcp.example.com/'],
            ResourceIndicators::from([
                'https://mcp.example.com/',
                'https://cloud.appwrite.io/v1/project1',
            ])->audience('https://cloud.appwrite.io/v1/project1')
        );
    }

    public function testAudienceReturnsStringWhenOnlyDefaultAudienceRemains(): void
    {
        $this->assertSame(
            'https://cloud.appwrite.io/v1/project1',
            ResourceIndicators::from([
                'https://cloud.appwrite.io/v1/project1',
            ])->audience('https://cloud.appwrite.io/v1/project1')
        );
    }
}
