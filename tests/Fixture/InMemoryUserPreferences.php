<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;

/** Ce qu'une personne aurait choisi dans son profil. */
final readonly class InMemoryUserPreferences implements UserPreferences
{
    /** @param array<string, array<string, bool|int>> $byUser */
    public function __construct(private array $byUser = [])
    {
    }

    public function valuesFor(string $userIdentifier): array
    {
        return $this->byUser[$userIdentifier] ?? [];
    }
}
