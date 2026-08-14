<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use Psr\Clock\ClockInterface;

/** Une heure qu'on pose, et qu'on avance à la main. */
final class FrozenClock implements ClockInterface
{
    public function __construct(private \DateTimeImmutable $now = new \DateTimeImmutable('2026-01-01 08:00:00'))
    {
    }

    public function now(): \DateTimeImmutable
    {
        return $this->now;
    }

    public function advance(int $seconds): void
    {
        $this->now = $this->now->modify(\sprintf('+%d seconds', $seconds));
    }
}
