<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes;

use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Forgettable;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/**
 * Range les empreintes des codes de secours dans une table à elles.
 *
 * Une table plutôt qu'une colonne sur les comptes : les codes s'ajoutent et disparaissent un à
 * un, et une application qui ne les active pas n'a pas à voir sa table de comptes changer.
 */
final readonly class DbalBackupCodes implements BackupCodeStore, Forgettable
{
    public const string TABLE = 'backup_codes';

    public function __construct(private Tables $tables)
    {
    }

    public function replaceAll(string $userIdentifier, array $hashes): void
    {
        $table = $this->table();
        $connection = $this->tables->connection();

        $connection->delete($table, ['user_identifier' => $userIdentifier]);

        foreach ($hashes as $hash) {
            $connection->insert($table, [
                'user_identifier' => $userIdentifier,
                'code_hash' => $hash,
            ]);
        }
    }

    public function hashesFor(string $userIdentifier): array
    {
        /** @var list<string> $hashes */
        $hashes = $this->tables->connection()->fetchFirstColumn(
            \sprintf('SELECT code_hash FROM %s WHERE user_identifier = ?', $this->table()),
            [$userIdentifier],
        );

        return $hashes;
    }

    public function forget(string $userIdentifier, string $hash): void
    {
        $this->tables->connection()->delete($this->table(), [
            'user_identifier' => $userIdentifier,
            'code_hash' => $hash,
        ]);
    }

    public function forgetEverythingOf(string $userIdentifier): void
    {
        $this->tables->connection()->delete($this->table(), ['user_identifier' => $userIdentifier]);
    }

    /** @return non-empty-string */
    private function table(): string
    {
        return $this->tables->ready(self::TABLE, static function (Table $table): void {
            // Pas de clé technique : le couple compte + empreinte est unique par nature, et
            // c'est lui qu'on interroge et qu'on retire.
            $table->addColumn('user_identifier', Types::STRING)->setLength(180)->setNotnull(true);
            $table->addColumn('code_hash', Types::STRING)->setLength(64)->setNotnull(true);
            $table->addIndex(['user_identifier'], 'idx_backup_codes_user');
            $table->addUniqueConstraint(['user_identifier', 'code_hash'], 'uniq_backup_codes_code');
        });
    }
}
