<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use PHPUnit\Framework\TestCase;

/**
 * Le refus de retirer le dernier moyen.
 *
 * C'est la seule chose qui sépare un compte protégé d'un compte perdu : personne, dans
 * l'application, ne peut redonner l'accès à quelqu'un qui n'a plus rien à présenter.
 */
final class FactorsTest extends TestCase
{
    public function testLeTotalAdditionneLesMecanismes(): void
    {
        $factors = new Factors([self::factor('totp', 1), self::factor('backup_codes', 8)], true);

        self::assertSame(9, $factors->countFor('claude'));
    }

    public function testLeDetailNommeChaqueMecanisme(): void
    {
        $factors = new Factors([self::factor('totp', 1), self::factor('backup_codes', 0)], true);

        self::assertSame(['totp' => 1, 'backup_codes' => 0], $factors->detailFor('claude'));
    }

    public function testRetirerCeQuiLaisseAutreChoseEstAutorise(): void
    {
        $factors = new Factors([self::factor('totp', 1), self::factor('backup_codes', 8)], true);

        $factors->requireRemovable('claude', 'backup_codes', 8);

        $this->expectNotToPerformAssertions();
    }

    public function testRetirerLeDernierMoyenEstRefuse(): void
    {
        $factors = new Factors([self::factor('backup_codes', 8)], true);

        $this->expectException(LastFactorRemoval::class);

        $factors->requireRemovable('claude', 'backup_codes', 8);
    }

    /**
     * Le compte porte sur ce qui resterait, pas sur ce qui existe : huit codes dont on retire
     * les huit ne laissent rien, même si huit paraissait confortable.
     */
    public function testLeCompteSeFaitSurCeQuiResterait(): void
    {
        $factors = new Factors([self::factor('backup_codes', 8)], true);

        $factors->requireRemovable('claude', 'backup_codes', 7);

        $this->expectNotToPerformAssertions();
    }

    /**
     * Une application qui n'exige rien n'a pas à protéger ses comptes contre eux-mêmes : elle
     * les laisse tout retirer, puisqu'un compte sans second facteur y entre encore.
     */
    public function testSansExigenceRienNEstRefuse(): void
    {
        $factors = new Factors([self::factor('backup_codes', 1)], false);

        $factors->requireRemovable('claude', 'backup_codes', 1);

        $this->expectNotToPerformAssertions();
    }

    /**
     * @param non-empty-string $name
     */
    private static function factor(string $name, int $count): Factor
    {
        return new class($name, $count) implements Factor {
            /**
             * @param non-empty-string $name
             */
            public function __construct(
                private readonly string $name,
                private readonly int $count,
            ) {
            }

            public function name(): string
            {
                return $this->name;
            }

            public function countFor(string $userIdentifier): int
            {
                return $this->count;
            }
        };
    }
}
