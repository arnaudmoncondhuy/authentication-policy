<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Forgettable;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/**
 * Range les clés dans une table à elles.
 *
 * L'identité opaque du compte est portée par la ligne plutôt que par une table à part : le
 * paquet ne connaît pas la clé primaire des comptes, et une table de plus pour une colonne
 * ajouterait une jointure à chaque cérémonie.
 */
final readonly class DbalSecurityKeys implements SecurityKeys, Forgettable
{
    public const string TABLE = 'security_keys';

    public function __construct(private Tables $tables)
    {
    }

    public function findAllOf(string $userIdentifier): array
    {
        $rows = $this->tables->connection()->fetchAllAssociative(
            \sprintf('SELECT * FROM %s WHERE user_identifier = ? ORDER BY created_at ASC', $this->table()),
            [$userIdentifier],
        );

        return array_map(self::hydrate(...), $rows);
    }

    public function findOneByCredentialId(string $rawCredentialId): ?StoredKey
    {
        return $this->oneWhere('credential_id = ?', [base64_encode($rawCredentialId)]);
    }

    public function findOneOf(string $userIdentifier, string $credentialId): ?StoredKey
    {
        return $this->oneWhere('user_identifier = ? AND credential_id = ?', [$userIdentifier, $credentialId]);
    }

    public function handleOf(string $userIdentifier): string
    {
        $held = $this->tables->connection()->fetchOne(
            \sprintf('SELECT user_handle FROM %s WHERE user_identifier = ?', $this->table()),
            [$userIdentifier],
        );

        // La première clé fabrique l'identité ; les suivantes reprennent la sienne, faute de
        // quoi un téléphone montrerait deux comptes là où il n'y en a qu'un.
        if (\is_string($held) && '' !== $held) {
            return $held;
        }

        $fabricated = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');

        return '' === $fabricated ? '0' : $fabricated;
    }

    public function save(StoredKey $key): void
    {
        $table = $this->table();
        $connection = $this->tables->connection();

        $connection->delete($table, ['credential_id' => $key->credentialId]);
        $connection->insert($table, [
            'credential_id' => $key->credentialId,
            'user_identifier' => $key->userIdentifier,
            'user_handle' => $key->userHandle,
            'label' => $key->label,
            'kind' => $key->kind->value,
            'record' => $key->record,
            'created_at' => $key->createdAt,
            'last_used_at' => $key->lastUsedAt,
        ]);
    }

    public function remove(StoredKey $key): void
    {
        $this->tables->connection()->delete($this->table(), ['credential_id' => $key->credentialId]);
    }

    public function noteUsage(StoredKey $key, string $record, int $at): void
    {
        $this->tables->connection()->update(
            $this->table(),
            ['record' => $record, 'last_used_at' => $at],
            ['credential_id' => $key->credentialId],
        );
    }

    public function forgetEverythingOf(string $userIdentifier): void
    {
        $this->tables->connection()->delete($this->table(), ['user_identifier' => $userIdentifier]);
    }

    /** @param list<mixed> $values */
    private function oneWhere(string $condition, array $values): ?StoredKey
    {
        $row = $this->tables->connection()->fetchAssociative(
            \sprintf('SELECT * FROM %s WHERE %s', $this->table(), $condition),
            $values,
        );

        return false === $row ? null : self::hydrate($row);
    }

    /** @param array<string, mixed> $row */
    private static function hydrate(array $row): StoredKey
    {
        $credentialId = (string) $row['credential_id'];
        $record = (string) $row['record'];

        return new StoredKey(
            '' === $credentialId ? '0' : $credentialId,
            (string) $row['user_identifier'],
            (string) $row['user_handle'],
            (string) $row['label'],
            Kind::tryFrom((string) $row['kind']) ?? Kind::Unknown,
            '' === $record ? '{}' : $record,
            (int) $row['created_at'],
            null === $row['last_used_at'] ? null : (int) $row['last_used_at'],
        );
    }

    /** @return non-empty-string */
    private function table(): string
    {
        return $this->tables->ready(self::TABLE, static function (Table $table): void {
            // L'identifiant est unique par nature — c'est la norme qui le garantit — et c'est
            // par lui qu'on retrouve une clé au moment où elle répond.
            $table->addColumn('credential_id', Types::STRING)->setLength(255)->setNotnull(true);
            $table->addColumn('user_identifier', Types::STRING)->setLength(180)->setNotnull(true);
            $table->addColumn('user_handle', Types::STRING)->setLength(88)->setNotnull(true);
            $table->addColumn('label', Types::STRING)->setLength(60)->setNotnull(true);
            $table->addColumn('kind', Types::STRING)->setLength(10)->setNotnull(true);
            $table->addColumn('record', Types::TEXT)->setNotnull(true);
            $table->addColumn('created_at', Types::BIGINT)->setNotnull(true);
            $table->addColumn('last_used_at', Types::BIGINT)->setNotnull(false);
            $table->addUniqueConstraint(['credential_id'], 'uniq_security_keys_credential');
            $table->addIndex(['user_identifier'], 'idx_security_keys_user');
        });
    }
}
