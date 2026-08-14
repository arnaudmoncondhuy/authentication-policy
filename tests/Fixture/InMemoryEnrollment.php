<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;

/** Qui a posé son second facteur, et qui ne l'a pas fait. */
final readonly class InMemoryEnrollment implements Enrollment
{
    /** @param list<string> $enrolled */
    public function __construct(private array $enrolled = [])
    {
    }

    public function isCompleteFor(string $userIdentifier): bool
    {
        return \in_array($userIdentifier, $this->enrolled, true);
    }
}
