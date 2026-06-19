<?php

namespace Utopia\Auth\OAuth2;

class ResourceIndicators
{
    /**
     * @return array<int, string>
     */
    public static function normalize(mixed $value): array
    {
        if ($value === null || $value === '') {
            return [];
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

        return $normalized;
    }

    public static function isValid(string $resource): bool
    {
        $parts = \parse_url($resource);

        return \is_array($parts)
            && !empty($parts['scheme'])
            && !isset($parts['fragment'])
            && (!empty($parts['host']) || !empty($parts['path']));
    }

    /**
     * @param array<int, string> $requested
     * @param array<int, string> $granted
     */
    public static function isSubset(array $requested, array $granted): bool
    {
        return empty(\array_diff($requested, $granted));
    }

    /**
     * @param array<int, string> $left
     * @param array<int, string> $right
     */
    public static function sameSet(array $left, array $right): bool
    {
        $sortedLeft = $left;
        $sortedRight = $right;
        \sort($sortedLeft, \SORT_STRING);
        \sort($sortedRight, \SORT_STRING);

        return $sortedLeft === $sortedRight;
    }

    /**
     * @param array<int, string> $resources
     * @return string|array<int, string>
     */
    public static function audience(string $defaultAudience, array $resources): string|array
    {
        if (empty($resources)) {
            return $defaultAudience;
        }

        $resourcesWithoutDefault = \array_values(
            \array_filter($resources, fn ($resource) => $resource !== $defaultAudience)
        );

        return \array_values(\array_merge([$defaultAudience], $resourcesWithoutDefault));
    }
}
