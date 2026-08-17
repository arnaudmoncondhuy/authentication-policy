<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\Authorization\Proof;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;

/**
 * Qui a le droit d'ajouter un moyen de se reconnaître.
 *
 * Poser son premier moyen ne peut rien exiger : un compte qui n'en a aucun n'a rien à présenter,
 * et le lui demander l'enfermerait dehors. Poser le suivant, si.
 *
 * C'est la seule ligne qui sépare « ma session a été volée » de « mon compte a changé de main » :
 * sans elle, un cookie dérobé pose son propre moyen, s'en sert pour se dire fraîchement
 * authentifié, et laisse derrière lui une clé qui survit au changement de mot de passe. Le niveau
 * exigé est donc {@see Proof::Recent} et non {@see Proof::Strong} : c'est précisément la session
 * dormante qu'il s'agit d'arrêter, et `Strong` la laisse passer par construction.
 */
final readonly class ProvenEnrollment
{
    public function __construct(
        private Factors $factors,
        // Absent quand le paquet qui juge les preuves n'est pas installé : les deux paquets
        // restent séparés, et celui-ci ne sait pas juger seul. Sans juge, il ne peut donc rien
        // exiger — c'est au docteur de dire que la garde ne s'applique pas.
        private ?ProofOfIdentity $identity,
    ) {
    }

    /**
     * Le compte peut-il poser un moyen de plus, maintenant.
     */
    public function allowsAdding(string $userIdentifier): bool
    {
        if (0 === $this->factors->countFor($userIdentifier)) {
            return true;
        }

        return $this->identity?->meets(Proof::Recent) ?? true;
    }

    /**
     * Le compte peut-il retirer un moyen, maintenant.
     *
     * Fermer l'entrée en laissant la sortie ne protégerait rien : retirer les moyens d'un compte
     * fait retomber sa preuve au niveau du mot de passe, et rouvre la porte qu'on venait de
     * fermer. La règle est donc la même, sans l'exception du premier — on ne retire pas ce qu'on
     * n'a pas.
     */
    public function allowsRemoving(string $userIdentifier): bool
    {
        return $this->identity?->meets(Proof::Recent) ?? true;
    }
}
