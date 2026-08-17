<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\Totp;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\TotpSecrets;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryTotpSecrets;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFactor;
use ParagonIE\ConstantTime\Base32;
use PHPUnit\Framework\TestCase;

/**
 * Ce qu'un code à six chiffres doit tenir : produire le nombre que la norme prévoit, ne compter
 * qu'une fois prouvé, et ne pas disparaître en emportant le dernier moyen d'entrer.
 */
final class TotpTest extends TestCase
{
    /**
     * Le secret d'éprouve de la RFC 6238, dérivé de sa forme lisible plutôt que recopié.
     *
     * C'est lui qui rend vérifiables les vecteurs de la norme, et donc qui prouve que le nombre
     * produit ici est celui qu'une application d'authentification affichera.
     *
     * @return non-empty-string
     */
    private static function rfcSecret(): string
    {
        $secret = Base32::encodeUpperUnpadded('12345678901234567890');

        return '' === $secret ? '0' : $secret;
    }

    public function testLeCodeProduitEstCeluiQueLaNormePrevoit(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $secrets->remember('arnaud', self::rfcSecret());
        $secrets->confirm('arnaud', 0);

        // T = 59 secondes après l'origine : le vecteur de la RFC rend 94287082 sur huit chiffres.
        $totp = $this->totp($secrets, at: 59, digits: 8);

        self::assertTrue($totp->verifyFor('arnaud', '94287082'));
        self::assertFalse($totp->verifyFor('arnaud', '94287083'));
    }

    /**
     * Un secret posé dont aucun code n'a prouvé le fonctionnement ne protège rien : le compter
     * fermerait le verrou sur quelqu'un qui ne peut produire aucun code.
     */
    public function testUnSecretNonConfirmeNeComptePas(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $totp = $this->totp($secrets);

        $totp->startFor('arnaud');

        self::assertSame(0, $totp->countFor('arnaud'));
        self::assertTrue($totp->awaitsConfirmationFor('arnaud'));
        self::assertFalse($totp->verifyFor('arnaud', '000000'));
    }

    public function testUnPremierCodeJusteFaitExisterLeMoyen(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $secrets->remember('arnaud', self::rfcSecret());

        $totp = $this->totp($secrets, at: 59, digits: 8);

        self::assertFalse($totp->confirmFor('arnaud', '00000000'));
        self::assertSame(0, $totp->countFor('arnaud'));

        self::assertTrue($totp->confirmFor('arnaud', '94287082'));
        self::assertSame(1, $totp->countFor('arnaud'));
    }

    /** Ce qu'on recopie depuis un écran porte des espaces ; les refuser ne protège de rien. */
    public function testLesEspacesRecopiesNeFontPasEchouerUnCodeJuste(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $secrets->remember('arnaud', self::rfcSecret());
        $secrets->confirm('arnaud', 0);

        self::assertTrue($this->totp($secrets, at: 59, digits: 8)->verifyFor('arnaud', '9428 7082'));
    }

    /**
     * Un code lu juste avant que la fenêtre ne tourne arrive après elle, et se ferait refuser
     * pour quelques secondes. La tolérance se règle, et vaut zéro tant qu'on ne l'a pas
     * demandée.
     */
    public function testLaToleranceRattrapeLaFenetreQuiVientDeTourner(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $secrets->remember('arnaud', self::rfcSecret());
        $secrets->confirm('arnaud', 0);

        // Le code de la fenêtre 30-60, présenté à la soixante-et-unième seconde.
        self::assertFalse($this->totp($secrets, at: 61, digits: 8)->verifyFor('arnaud', '94287082'));
        self::assertTrue($this->totp($secrets, at: 61, digits: 8, leeway: 5)->verifyFor('arnaud', '94287082'));
    }

    public function testRetirerLeDernierMoyenEstRefuse(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $secrets->remember('arnaud', self::rfcSecret());
        $secrets->confirm('arnaud', 0);

        $this->expectException(LastFactorRemoval::class);

        $this->totp($secrets, required: true)->forgetFor('arnaud');
    }

    public function testPoserUnSecretNeufRemplaceCeluiQuiAttendait(): void
    {
        $secrets = new InMemoryTotpSecrets();
        $totp = $this->totp($secrets);

        $totp->startFor('arnaud');
        $premier = $secrets->secretOf('arnaud');

        $totp->startFor('arnaud');

        self::assertNotSame($premier, $secrets->secretOf('arnaud'));
    }

    private function totp(
        TotpSecrets $secrets,
        int $at = 0,
        int $digits = 6,
        int $leeway = 0,
        bool $required = false,
    ): Totp {
        // L'origine des vecteurs de la norme est l'époque Unix : l'horloge du test s'y place.
        return new Totp(
            $secrets,
            // Le seul moyen du compte quand on exige quelque chose de lui : c'est ce qui rend
            // son retrait refusable.
            new Factors($required ? [new StubFactor(1, Totp::NAME)] : [], $required),
            new FrozenClock(new \DateTimeImmutable('@'.$at)),
            'Le test',
            null,
            $digits,
            30,
            'sha1',
            $leeway,
        );
    }
}
