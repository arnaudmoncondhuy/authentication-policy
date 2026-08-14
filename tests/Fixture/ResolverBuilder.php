<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Decisions;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;

/** Monte un résolveur en trois lignes, pour que les tests parlent de politique et non de plomberie. */
final class ResolverBuilder
{
    /** @var array<string, array<string, bool|int>> */
    private array $roles = [];

    /** @var array<string, array<string, bool|int>> */
    private array $preferences = [];

    public function __construct(private readonly Policy $policy)
    {
    }

    /** @param array<string, array<string, bool|int>> $roles */
    public function withRoles(array $roles): self
    {
        $this->roles = $roles;

        return $this;
    }

    /** @param array<string, array<string, bool|int>> $preferences */
    public function withPreferences(array $preferences): self
    {
        $this->preferences = $preferences;

        return $this;
    }

    public function decideFor(string $identifier, string ...$roles): Decisions
    {
        return $this->resolver()->decideFor($identifier, ...$roles);
    }

    public function resolver(): PolicyResolver
    {
        return new PolicyResolver(
            $this->policy,
            new InMemoryRolePolicies($this->roles),
            new InMemoryUserPreferences($this->preferences),
        );
    }
}
