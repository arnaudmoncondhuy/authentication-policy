<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Storage;

use ArnaudMoncondhuy\AuthenticationPolicy\Kind;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/**
 * Ce qu'une personne a choisi pour elle-même, rangé par le paquet.
 *
 * Une ligne par réglage plutôt qu'une colonne par réglage : l'énumération des réglages est
 * fermée mais elle s'allonge, et une colonne de plus demanderait une migration à toutes les
 * applications installées.
 *
 * Un choix plus large que le plafond reste écrit tel quel — la résolution le ramène. C'est ce
 * qui permet de desserrer la politique plus tard sans redemander à chacun ce qu'il voulait.
 */
final readonly class DbalUserPreferences implements UserPreferences, Forgettable
{
    public const string TABLE = 'preferences';

    public function __construct(private Tables $tables)
    {
    }

    public function valuesFor(string $userIdentifier): array
    {
        $rows = $this->tables->connection()->fetchAllAssociative(
            \sprintf('SELECT setting, value FROM %s WHERE user_identifier = ?', $this->table()),
            [$userIdentifier],
        );

        $values = [];

        foreach ($rows as $row) {
            // Un réglage disparu de l'énumération lève ici, et c'est le comportement voulu :
            // une préférence qu'on ne sait plus lire ne doit pas passer pour absente.
            $setting = Setting::ofId((string) $row['setting']);

            $values[$setting->value] = Kind::Duration === $setting->kind()
                ? (int) $row['value']
                : '1' === (string) $row['value'];
        }

        return $values;
    }

    public function remember(string $userIdentifier, array $values): void
    {
        $table = $this->table();
        $connection = $this->tables->connection();

        foreach ($values as $id => $value) {
            $setting = Setting::ofId($id);

            // Retrait puis pose : `INSERT … ON CONFLICT` n'a pas d'écriture commune aux bases
            // que Doctrine sert.
            $connection->delete($table, [
                'user_identifier' => $userIdentifier,
                'setting' => $setting->value,
            ]);

            if (null === $value) {
                continue;
            }

            $connection->insert($table, [
                'user_identifier' => $userIdentifier,
                'setting' => $setting->value,
                'value' => \is_bool($value) ? ($value ? '1' : '0') : (string) $value,
            ]);
        }
    }

    public function forgetEverythingOf(string $userIdentifier): void
    {
        $this->tables->connection()->delete($this->table(), ['user_identifier' => $userIdentifier]);
    }

    /** @return non-empty-string */
    private function table(): string
    {
        return $this->tables->ready(self::TABLE, static function (Table $table): void {
            $table->addColumn('user_identifier', Types::STRING)->setLength(180)->setNotnull(true);
            $table->addColumn('setting', Types::STRING)->setLength(32)->setNotnull(true);
            $table->addColumn('value', Types::STRING)->setLength(20)->setNotnull(true);
            // Une contrainte d'unicité plutôt qu'une clé primaire : le couple est unique par
            // nature, et c'est lui qu'on interroge et qu'on remplace.
            $table->addIndex(['user_identifier'], 'idx_preferences_user');
            $table->addUniqueConstraint(['user_identifier', 'setting'], 'uniq_preferences_setting');
        });
    }
}
