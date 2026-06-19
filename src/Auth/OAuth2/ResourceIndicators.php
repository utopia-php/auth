<?php

namespace Utopia\Auth\OAuth2;

class ResourceIndicators
{
    /**
     * @var array<int, string>
     */
    private array $resources;

    /**
     * @param array<int, string> $resources
     */
    private function __construct(array $resources)
    {
        if ($resources !== \array_values($resources)) {
            throw new \InvalidArgumentException('resources must be a list of absolute URIs.');
        }

        $seen = [];

        foreach ($resources as $resource) {
            if (!\is_string($resource) || $resource === '') {
                throw new \InvalidArgumentException('resource must be a non-empty absolute URI.');
            }

            if (!self::isValid($resource)) {
                throw new \InvalidArgumentException('resource must be an absolute URI without a fragment.');
            }

            if (\in_array($resource, $seen, true)) {
                throw new \InvalidArgumentException('resources must not contain duplicates.');
            }

            $seen[] = $resource;
        }

        $this->resources = $resources;
    }

    /**
     * @param string|array<int, mixed>|null $value
     */
    public static function from(string|array|null $value): self
    {
        if ($value === null || $value === '') {
            return new self([]);
        }

        $resources = \is_array($value) ? $value : [$value];
        $normalized = [];

        foreach ($resources as $resource) {
            if (!\is_string($resource) || $resource === '') {
                throw new \InvalidArgumentException('resource must be a non-empty absolute URI.');
            }

            if (!self::isValid($resource)) {
                throw new \InvalidArgumentException('resource must be an absolute URI without a fragment.');
            }

            if (!\in_array($resource, $normalized, true)) {
                $normalized[] = $resource;
            }
        }

        return new self($normalized);
    }

    public function isSubsetOf(self $granted): bool
    {
        return empty(\array_diff($this->resources, $granted->resources));
    }

    public function equals(self $resources): bool
    {
        $left = $this->resources;
        $right = $resources->resources;
        \sort($left, \SORT_STRING);
        \sort($right, \SORT_STRING);

        return $left === $right;
    }

    /**
     * @return array<int, string>
     */
    public function audience(string $defaultAudience): array
    {
        $resourcesWithoutDefault = \array_values(
            \array_filter($this->resources, fn ($resource) => $resource !== $defaultAudience)
        );

        $audience = [$defaultAudience, ...$resourcesWithoutDefault];

        return $audience;
    }

    /**
     * @return array<int, string>
     */
    public function toArray(): array
    {
        return $this->resources;
    }

    private static function isValid(string $resource): bool
    {
        $parts = \parse_url($resource);

        return \is_array($parts)
            && !empty($parts['scheme'])
            && !isset($parts['fragment'])
            && (!empty($parts['host']) || !empty($parts['path']));
    }
}
