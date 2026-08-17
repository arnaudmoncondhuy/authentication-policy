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

        // Hors de son périmètre, ce juge ne sait rien : il ne voit ni la session, ni ce qui y a
        // été présenté. Répondre « oui » reviendrait à accorder par les portes qu'il ne garde pas
        // ce qu'il refuse sur celles qu'il garde — une console, une file, un pare-feu machine
        // deviendraient le chemin le plus court vers un droit qui exigeait une preuve.
        //
        // Ce qu'on ne peut pas établir, on le refuse. C'est aussi la règle du paquet qui pose la
        // question : sans juge, il arrête la compilation plutôt que de laisser passer.
        if (!$this->visitor->isGoverned()) {
            return false;
        }

        $identifier = $this->visitor->identifierOrNull();

        // Personne n'est connecté : rien n'est prouvé. Le cas ne devrait pas se présenter — le
        // droit est vérifié avant, et un anonyme n'en a aucun — mais s'il se présente, il se
        // referme.
        if (null === $identifier) {
            return false;
        }

        // Le compte doit être protégé…
        if ($this->factors->countFor($identifier) < 1) {
            return false;
        }

        $age = $this->moment->ageInSeconds();

        // …et l'avoir présenté DANS CETTE SESSION. Un moyen posé ne prouve rien à lui seul : il
        // dit ce que le compte pourrait montrer, pas ce que la personne devant l'écran a montré.
        // Sans cette seconde condition, un compte équipé serait réputé fort à la seconde où il
        // entre — y compris par un chemin qui n'a jamais réclamé son moyen, un « se souvenir de
        // moi », un appareil de confiance, ou une politique qui n'exige rien. C'est-à-dire
        // exactement le mot de passe volé que ce niveau prétend arrêter.
        if (null === $age) {
            return false;
        }

        if (Proof::Strong === $required) {
            return true;
        }

        return $age <= $this->freshness;
    }
}
