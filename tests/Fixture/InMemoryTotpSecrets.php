<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\TotpSecrets;

/** Un rangement en mémoire : les tests portent sur le mécanisme, jamais sur une base. */
final class InMemoryTotpSecrets implements TotpSecrets
{
    /** @var array<string, array{secret: non-empty-string, confirmed_at: int|null}> */
    private array $secrets = [];

    public function secretOf(string $userIdentifier): ?string
    {
        return $this->secrets[$userIdentifier]['secret'] ?? null;
    }

    public function confirmedSecretOf(string $userIdentifier): ?string
    {
        $held = $this->secrets[$userIdentifier] ?? null;

        return null !== $held && null !== $held['confirmed_at'] ? $held['secret'] : null;
    }

    public function remember(string $userIdentifier, string $secret): void
    {
        $this->secrets[$userIdentifier] = ['secret' => $secret, 'confirmed_at' => null];
    }

    public function confirm(string $userIdentifier, int $at): void
    {
        if (isset($this->secrets[$userIdentifier])) {
            $this->secrets[$userIdentifier]['confirmed_at'] = $at;
        }
    }

    public function forget(string $userIdentifier): void
    {
        unset($this->secrets[$userIdentifier]);
    }
}
