<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Firewall;

/** Le pare-feu sous lequel le test se place. */
final readonly class StubFirewall implements Firewall
{
    public function __construct(private ?string $name = 'main')
    {
    }

    public function name(): ?string
    {
        return $this->name;
    }
}
