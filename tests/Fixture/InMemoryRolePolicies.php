<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;

/** Ce qu'une administration aurait posé sur des rôles, sans base pour le ranger. */
final readonly class InMemoryRolePolicies implements RolePolicies
{
    /** @param array<string, array<string, bool|int>> $byRole */
    public function __construct(private array $byRole = [])
    {
    }

    public function valuesFor(string $role): array
    {
        return $this->byRole[$role] ?? [];
    }
}
