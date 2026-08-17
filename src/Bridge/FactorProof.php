<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\Authorization\Proof;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;

/**
 * Ce que ce paquet sait dire de l'identité, à qui décide des droits.
 *
 * Le pont entre les deux paquets, et il ne va que dans ce sens : `authorization` nomme les
 * niveaux sans savoir ce qu'authentifier veut dire, celui-ci le sait et ne connaît aucun droit.
 * Il n'est déclaré que si le contrat existe et qu'un mécanisme est allumé — sans quoi il ne
 * pourrait répondre que non, et une action protégée deviendrait inatteignable par tout le monde
 * sans que rien ne le dise.
 *
 * **Hors du périmètre, il ne se prononce pas et laisse passer.** Une machine ne pose pas de
 * second facteur et n'en présentera jamais : lui opposer un détour la mettrait dehors sans
 * porte, et la porte n'existe pas pour elle. C'est la règle de tout le paquet — ce qui n'est
 * pas nommé dans `firewalls` lui échappe, par construction. Une action qu'on veut réserver aux
 * personnes se ferme par un droit, qui lui sait le faire.
 */
final readonly class FactorProof implements ProofOfIdentity
{
    /**
     * @param int $freshness au-delà de combien de secondes une preuve cesse d'être récente
     */
    public function __construct(
        private Factors $factors,
        private Visitor $visitor,
        private ProvenMoment $moment,
        private int $freshness,
    ) {
    }

    public function meets(Proof $required): bool
    {
        if (Proof::None === $required) {
            return true;
        }

        if (!$this->visitor->isGoverned()) {
            return true;
        }

        $identifier = $this->visitor->identifierOrNull();

        // Personne n'est connecté : rien n'est prouvé. Le cas ne devrait pas se présenter — le
        // droit est vérifié avant, et un anonyme n'en a aucun — mais s'il se présente, il se
        // referme.
        if (null === $identifier) {
            return false;
        }

        // Le compte est protégé, et l'a donc présenté pour ouvrir cette session : le paquet
        // réclame un moyen dès qu'il en existe un.
        if ($this->factors->countFor($identifier) < 1) {
            return false;
        }

        if (Proof::Strong === $required) {
            return true;
        }

        $age = $this->moment->ageInSeconds();

        return null !== $age && $age <= $this->freshness;
    }
}
