<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodeStore;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/**
 * Range les empreintes des codes de secours dans une table à elles.
 *
 * Une table plutôt qu'une colonne sur les comptes : les codes s'ajoutent et disparaissent un à
 * un, et une application qui ne les active pas n'a pas à voir sa table de comptes changer.
 *
 * La table se crée toute seule à la première écriture, comme le fait la file de messages : une
 * application qui allume les codes de secours n'a alors rien à migrer. Qui préfère la tenir
 * lui-même coupe `auto_setup` et la déclare dans ses propres migrations.
 */
final class DbalBackupCodeStore implements BackupCodeStore
{
    public const string TABLE = 'authentication_backup_codes';

    private bool $checked = false;

    public function __construct(
        private readonly Connection $connection,
        private readonly bool $autoSetup = true,
    ) {
    }

    public function replaceAll(string $userIdentifier, array $hashes): void
    {
        $this->prepare();

        $this->connection->delete(self::TABLE, ['user_identifier' => $userIdentifier]);

        foreach ($hashes as $hash) {
            $this->connection->insert(self::TABLE, [
                'user_identifier' => $userIdentifier,
                'code_hash' => $hash,
            ]);
        }
    }

    public function hashesFor(string $userIdentifier): array
    {
        $this->prepare();

        /** @var list<string> $hashes */
        $hashes = $this->connection->fetchFirstColumn(
            \sprintf('SELECT code_hash FROM %s WHERE user_identifier = ?', self::TABLE),
            [$userIdentifier],
        );

        return $hashes;
    }

    public function forget(string $userIdentifier, string $hash): void
    {
        $this->prepare();

        $this->connection->delete(self::TABLE, [
            'user_identifier' => $userIdentifier,
            'code_hash' => $hash,
        ]);
    }

    /**
     * La vérification n'a lieu qu'une fois par requête : la faire à chaque code interrogerait
     * le schéma dix fois pour une seule connexion.
     */
    private function prepare(): void
    {
        if ($this->checked || !$this->autoSetup) {
            return;
        }

        $this->checked = true;

        $schema = $this->connection->createSchemaManager();

        if ($schema->tablesExist([self::TABLE])) {
            return;
        }

        // Pas de clé technique : le couple compte + empreinte est unique par nature, et c'est
        // lui qu'on interroge et qu'on retire.
        $table = new Table(self::TABLE);
        $table->addColumn('user_identifier', Types::STRING)->setLength(180)->setNotnull(true);
        $table->addColumn('code_hash', Types::STRING)->setLength(64)->setNotnull(true);
        $table->addIndex(['user_identifier'], 'idx_backup_codes_user');
        $table->addUniqueConstraint(['user_identifier', 'code_hash'], 'uniq_backup_codes_code');

        $schema->createTable($table);
    }
}
