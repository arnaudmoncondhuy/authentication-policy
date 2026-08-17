<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use OTPHP\TOTP as Generator;
use Psr\Clock\ClockInterface;

/**
 * Le code à six chiffres d'une application d'authentification.
 *
 * Un secret partagé, posé une fois, dont l'appareil et le serveur tirent le même nombre à la
 * même seconde. Rien ne circule au moment de s'en servir : c'est ce qui le distingue d'un code
 * envoyé par message, qu'on peut intercepter ou faire réémettre.
 *
 * **Un secret non confirmé ne compte pas.** Tant qu'aucun code juste n'a été présenté, rien ne
 * prouve que l'application d'authentification ait lu le bon QR code — et compter ce moyen
 * fermerait le verrou sur quelqu'un qui ne peut produire aucun code.
 */
final readonly class Totp implements Factor
{
    public const string NAME = 'totp';

    /** Cent soixante bits, ce que recommande la norme pour un secret partagé. */
    private const int SECRET_BYTES = 20;

    public function __construct(
        private TotpSecrets $secrets,
        private Factors $factors,
        private ClockInterface $clock,
        private string $issuer = '',
        private ?string $serverName = null,
        private int $digits = 6,
        private int $period = 30,
        private string $algorithm = 'sha1',
        private int $leeway = 0,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function countFor(string $userIdentifier): int
    {
        return null === $this->secrets->confirmedSecretOf($userIdentifier) ? 0 : 1;
    }

    public function manageAt(): string
    {
        return 'authentication_policy_totp';
    }

    public function isRecovery(): bool
    {
        return false;
    }

    /** Y a-t-il un secret posé qu'aucun code n'a encore confirmé. */
    public function awaitsConfirmationFor(string $userIdentifier): bool
    {
        return null !== $this->secrets->secretOf($userIdentifier)
            && null === $this->secrets->confirmedSecretOf($userIdentifier);
    }

    /**
     * Pose un secret neuf, en attente de confirmation.
     *
     * Il remplace celui qui attendait : recommencer l'enrôlement doit produire un code qui
     * fonctionne, et non ressusciter celui qu'on avait renoncé à photographier.
     */
    public function startFor(string $userIdentifier): void
    {
        // Vingt octets : ce que la norme prévoit, et ce que les applications d'authentification
        // attendent. Le défaut de la bibliothèque en fait trois fois plus, soit une clé de cent
        // caractères que personne ne recopie à la main quand l'appareil photo manque.
        $this->secrets->remember(
            $userIdentifier,
            Generator::generate($this->clock, self::SECRET_BYTES)->getSecret(),
        );
    }

    /**
     * L'adresse `otpauth://` du secret en attente, celle que le QR code encode.
     *
     * Reconstruite à chaque affichage plutôt que transportée : l'écran se recharge, se partage
     * et se revisite sans que la manipulation ait à recommencer.
     */
    public function enrolmentUriFor(string $userIdentifier): ?string
    {
        $secret = $this->secrets->secretOf($userIdentifier);

        return null === $secret || null !== $this->secrets->confirmedSecretOf($userIdentifier)
            ? null
            : $this->generatorFor($secret, $userIdentifier)->getProvisioningUri();
    }

    /** Le secret en toutes lettres, pour qui ne peut pas photographier. */
    public function secretFor(string $userIdentifier): ?string
    {
        return $this->secrets->secretOf($userIdentifier);
    }

    /**
     * Confirme le secret posé si le code présenté en découle.
     *
     * C'est cette étape qui fait exister le moyen : avant elle, le compte n'a rien.
     */
    public function confirmFor(string $userIdentifier, string $code): bool
    {
        $secret = $this->secrets->secretOf($userIdentifier);

        if (null === $secret || !$this->accepts($secret, $code)) {
            return false;
        }

        $this->secrets->confirm($userIdentifier, $this->clock->now()->getTimestamp());

        return true;
    }

    /** Le contrôle de la connexion : seul un secret confirmé ouvre. */
    public function verifyFor(string $userIdentifier, string $code): bool
    {
        $secret = $this->secrets->confirmedSecretOf($userIdentifier);

        return null !== $secret && $this->accepts($secret, $code);
    }

    /** @throws LastFactorRemoval si le compte n'a rien d'autre pour se connecter */
    public function forgetFor(string $userIdentifier): void
    {
        $this->factors->requireRemovable($userIdentifier, $this->name(), $this->countFor($userIdentifier));

        $this->secrets->forget($userIdentifier);
    }

    /**
     * Ce qui est recopié depuis un écran porte des espaces : les refuser rejetterait un code
     * juste sans rien protéger.
     */
    /** @param non-empty-string $secret */
    private function accepts(string $secret, string $code): bool
    {
        $typed = (string) preg_replace('/\s+/', '', $code);

        return '' !== $typed
            && $this->generatorFor($secret, '')->verify($typed, null, max(0, $this->leeway));
    }

    /** @param non-empty-string $secret */
    private function generatorFor(string $secret, string $userIdentifier): Generator
    {
        $generator = Generator::createFromSecret($secret, $this->clock)
            ->withPeriod(max(1, $this->period))
            ->withDigits(max(1, $this->digits))
            ->withDigest('' === $this->algorithm ? 'sha1' : $this->algorithm)
        ;

        if ('' !== $userIdentifier) {
            // Ce que la liste de l'application affiche. Le nom de serveur distingue deux
            // installations du même service, qu'on aurait sinon deux fois sous le même libellé.
            $generator = $generator->withLabel(null === $this->serverName || '' === $this->serverName
                ? $userIdentifier
                : $userIdentifier.'@'.$this->serverName);
        }

        if ('' !== $this->issuer) {
            $generator = $generator->withIssuer($this->issuer);
        }

        return $generator;
    }
}
