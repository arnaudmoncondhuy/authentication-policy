<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFactor;
use ArnaudMoncondhuy\Authorization\Proof;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use PHPUnit\Framework\TestCase;

/**
 * Qui a le droit d'ajouter ou de retirer un moyen de se reconnaître.
 *
 * C'est la ligne qui sépare « ma session a été volée » de « mon compte a changé de main » : sans
 * elle, un cookie dérobé pose son propre moyen, s'en sert pour se dire fraîchement authentifié,
 * et laisse derrière lui une clé qui survit au changement de mot de passe.
 */
final class ProvenEnrollmentTest extends TestCase
{
    public function testPoserSonPremierMoyenNExigeRien(): void
    {
        $enrollment = new ProvenEnrollment(self::factors(0), self::proof(meets: false));

        self::assertTrue($enrollment->allowsAdding('arnaud'));
    }

    public function testPoserUnMoyenDePlusExigeUneIdentiteProuveeRecemment(): void
    {
        $enrollment = new ProvenEnrollment(self::factors(1), self::proof(meets: false));

        self::assertFalse($enrollment->allowsAdding('arnaud'));
    }

    public function testUneIdentiteProuveeRecemmentPeutPoserUnMoyenDePlus(): void
    {
        $enrollment = new ProvenEnrollment(self::factors(1), self::proof(meets: true));

        self::assertTrue($enrollment->allowsAdding('arnaud'));
    }

    public function testRetirerUnMoyenExigeUneIdentiteProuveeRecemment(): void
    {
        $enrollment = new ProvenEnrollment(self::factors(2), self::proof(meets: false));

        self::assertFalse($enrollment->allowsRemoving('arnaud'));
    }

    /**
     * Les deux paquets restent séparés : celui-ci ne sait pas juger seul, et une application qui
     * n'a pas installé le juge ne doit pas se retrouver incapable d'équiper ses comptes. C'est
     * au docteur de dire que la garde ne s'applique pas — pas à cette classe de la simuler.
     */
    public function testSansJugeLaGardeNExigeRien(): void
    {
        $enrollment = new ProvenEnrollment(self::factors(3), null);

        self::assertTrue($enrollment->allowsAdding('arnaud'));
        self::assertTrue($enrollment->allowsRemoving('arnaud'));
    }

    /**
     * Le niveau exigé est bien « récent » et non « fort » : c'est la session dormante qu'il
     * s'agit d'arrêter, et « fort » la laisse passer par construction, puisqu'il se contente de
     * constater qu'un moyen est posé.
     */
    public function testLeNiveauExigeEstLaFraicheurEtPasSeulementLaForce(): void
    {
        $juge = new class implements ProofOfIdentity {
            public ?Proof $demande = null;

            public function meets(Proof $required): bool
            {
                $this->demande = $required;

                return true;
            }
        };

        (new ProvenEnrollment(self::factors(1), $juge))->allowsAdding('arnaud');

        self::assertSame(Proof::Recent, $juge->demande);
    }

    private static function factors(int $poses): Factors
    {
        return new Factors([new StubFactor($poses)], required: false);
    }

    private static function proof(bool $meets): ProofOfIdentity
    {
        return new class($meets) implements ProofOfIdentity {
            public function __construct(private bool $meets)
            {
            }

            public function meets(Proof $required): bool
            {
                return $this->meets;
            }
        };
    }
}
