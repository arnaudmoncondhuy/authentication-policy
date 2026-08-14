<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Un réglage d'authentification que la politique gouverne.
 *
 * L'énumération est fermée, et c'est volontaire : un paquet qui laisserait une application
 * ajouter ses propres réglages ne pourrait plus rien garantir sur eux — ni qu'ils ont un
 * plafond, ni qu'ils ont un stockage, ni que quelqu'un les applique. Ce qui n'est pas ici
 * appartient au projet, qui le règle comme il l'entend.
 *
 * Chaque réglage dit qui l'applique. La distinction n'est pas cosmétique : un réglage
 * qu'aucun code n'applique est une case qui ment, et {@see Setting::enforcedHere()} est ce que
 * `authentication-policy:doctor` affiche pour qu'on ne s'y trompe pas.
 *
 * L'identité est stable : c'est elle qui se retrouve en base, dans les préférences d'une
 * personne et dans les réglages d'un rôle. La renommer sans reprendre les lignes déjà écrites
 * fait échouer la résolution — bruyamment, ce qui est le comportement voulu.
 */
enum Setting: string
{
    /** Le second facteur est-il exigé de cette personne. */
    case TwoFactor = 'two_factor';

    /** Des codes de secours doivent-ils exister avant de pouvoir entrer. */
    case BackupCodes = 'backup_codes';

    /** Le navigateur peut-il être retenu pour ne plus redemander le second facteur. */
    case TrustedDevice = 'trusted_device';

    /** La connexion peut-elle survivre à la fermeture du navigateur. */
    case RememberMe = 'remember_me';

    /** Secondes d'inactivité au-delà desquelles la session tombe. */
    case IdleTimeout = 'idle_timeout';

    /** Secondes depuis la connexion au-delà desquelles la session tombe, active ou non. */
    case AbsoluteTimeout = 'absolute_timeout';

    public function kind(): Kind
    {
        return match ($this) {
            self::TwoFactor, self::BackupCodes => Kind::Requirement,
            self::TrustedDevice, self::RememberMe => Kind::Permission,
            self::IdleTimeout, self::AbsoluteTimeout => Kind::Duration,
        };
    }

    /**
     * Vrai quand le paquet applique lui-même le réglage, faux quand il se contente de le
     * résoudre et que le projet en tire les conséquences.
     *
     * Ce qui est résolu ici et appliqué ailleurs n'est pas un défaut : le paquet ne fabrique
     * aucun mécanisme. Il dit ce qui est exigé de qui, et le mécanisme installé — un second
     * facteur, un cookie de longue durée — obéit. Mais il faut que ce soit lisible, sans quoi
     * on croit tenu ce qui ne l'est pas.
     */
    public function enforcedHere(): bool
    {
        return match ($this) {
            self::TwoFactor, self::IdleTimeout, self::AbsoluteTimeout => true,
            self::BackupCodes, self::TrustedDevice, self::RememberMe => false,
        };
    }

    /** @return list<self> */
    public static function all(): array
    {
        return self::cases();
    }

    /** @throws UnknownSetting */
    public static function ofId(string $id): self
    {
        return self::tryFrom($id) ?? throw new UnknownSetting(\sprintf('Le réglage « %s » n\'existe pas. Réglages connus : %s.', $id, implode(', ', array_column(self::cases(), 'value'))));
    }
}
