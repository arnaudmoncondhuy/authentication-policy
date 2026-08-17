<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;

/** Ce qu'une personne aurait choisi dans son profil. */
final class InMemoryUserPreferences implements UserPreferences
{
    /** @param array<string, array<string, bool|int>> $byUser */
    public function __construct(private array $byUser = [])
    {
    }

    public function valuesFor(string $userIdentifier): array
    {
        return $this->byUser[$userIdentifier] ?? [];
    }

    public function remember(string $userIdentifier, array $values): void
    {
        foreach ($values as $setting => $value) {
            if (null === $value) {
                unset($this->byUser[$userIdentifier][$setting]);

                continue;
            }

            $this->byUser[$userIdentifier][$setting] = $value;
        }
    }
}
