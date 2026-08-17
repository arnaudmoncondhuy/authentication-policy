<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;

/** Un moyen posé un certain nombre de fois, pour éprouver ce qui compte les moyens. */
final readonly class StubFactor implements Factor
{
    public function __construct(
        private int $count = 0,
        private string $name = 'un_moyen',
        private bool $recovery = false,
    ) {
    }

    public function name(): string
    {
        return '' === $this->name ? 'un_moyen' : $this->name;
    }

    public function countFor(string $userIdentifier): int
    {
        return $this->count;
    }

    public function manageAt(): string
    {
        return 'page_du_moyen';
    }

    public function isRecovery(): bool
    {
        return $this->recovery;
    }
}
