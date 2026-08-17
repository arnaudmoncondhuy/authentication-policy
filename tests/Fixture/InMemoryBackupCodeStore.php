<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture;

use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodeStore;

/**
 * Un rangement en mémoire : les tests portent sur le mécanisme, jamais sur une base.
 */
final class InMemoryBackupCodeStore implements BackupCodeStore
{
    /** @var array<string, list<string>> */
    private array $hashes = [];

    public function replaceAll(string $userIdentifier, array $hashes): void
    {
        $this->hashes[$userIdentifier] = $hashes;
    }

    public function hashesFor(string $userIdentifier): array
    {
        return $this->hashes[$userIdentifier] ?? [];
    }

    public function forget(string $userIdentifier, string $hash): void
    {
        $this->hashes[$userIdentifier] = array_values(
            array_filter($this->hashes[$userIdentifier] ?? [], static fn (string $kept): bool => $kept !== $hash),
        );
    }
}
