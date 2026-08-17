<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Forgettable;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Doctrine\DBAL\Schema\Table;
use Doctrine\DBAL\Types\Types;

/**
 * Range les secrets partagés dans une table à eux.
 *
 * Une ligne par compte : poser un secret neuf remplace le précédent, faute de quoi l'ancien
 * continuerait d'ouvrir la porte.
 *
 * Le secret est rangé tel quel, et c'est inévitable : il faut le rendre pour fabriquer le code
 * attendu, ce qu'une empreinte ne permettrait pas. C'est pourquoi il vit dans une table à part,
 * qu'une application peut chiffrer ou déplacer en nommant son propre rangement.
 */
final readonly class DbalTotpSecrets implements TotpSecrets, Forgettable
{
    public const string TABLE = 'totp_secrets';

    public function __construct(private Tables $tables)
    {
    }

    public function secretOf(string $userIdentifier): ?string
    {
        $secret = $this->tables->connection()->fetchOne(
            \sprintf('SELECT secret FROM %s WHERE user_identifier = ?', $this->table()),
            [$userIdentifier],
        );

        return \is_string($secret) && '' !== $secret ? $secret : null;
    }

    public function confirmedSecretOf(string $userIdentifier): ?string
    {
        $secret = $this->tables->connection()->fetchOne(
            \sprintf('SELECT secret FROM %s WHERE user_identifier = ? AND confirmed_at IS NOT NULL', $this->table()),
            [$userIdentifier],
        );

        return \is_string($secret) && '' !== $secret ? $secret : null;
    }

    public function remember(string $userIdentifier, string $secret): void
    {
        $table = $this->table();
        $connection = $this->tables->connection();

        $connection->delete($table, ['user_identifier' => $userIdentifier]);
        $connection->insert($table, [
            'user_identifier' => $userIdentifier,
            'secret' => $secret,
            'confirmed_at' => null,
        ]);
    }

    public function confirm(string $userIdentifier, int $at): void
    {
        $this->tables->connection()->update(
            $this->table(),
            ['confirmed_at' => $at],
            ['user_identifier' => $userIdentifier],
        );
    }

    public function forget(string $userIdentifier): void
    {
        $this->tables->connection()->delete($this->table(), ['user_identifier' => $userIdentifier]);
    }

    public function forgetEverythingOf(string $userIdentifier): void
    {
        $this->forget($userIdentifier);
    }

    /** @return non-empty-string */
    private function table(): string
    {
        return $this->tables->ready(self::TABLE, static function (Table $table): void {
            $table->addColumn('user_identifier', Types::STRING)->setLength(180)->setNotnull(true);
            $table->addColumn('secret', Types::STRING)->setLength(255)->setNotnull(true);
            // Des secondes plutôt qu'une date : le paquet a une horloge, pas un fuseau.
            $table->addColumn('confirmed_at', Types::BIGINT)->setNotnull(false);
            $table->addUniqueConstraint(['user_identifier'], 'uniq_totp_user');
        });
    }
}
