<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Un moyen qui sait se faire redemander, dans une session déjà ouverte.
 *
 * Se poser une fois et se redemander ne sont pas la même chose. Un moyen se pose à
 * l'enrôlement et se présente à la connexion — l'étape de connexion s'en charge. Ce contrat
 * sert à autre chose : redemander la preuve **au milieu du travail**, devant un acte qui le
 * mérite, sans faire ressortir personne de sa session.
 *
 * Séparé de {@see Factor} parce que tous les moyens n'en sont pas capables : un moyen posé
 * ailleurs — un appareil de confiance, une signature reçue par un tiers — se compte et
 * s'affiche sans qu'on puisse le redemander à volonté. L'écran de redemande n'affiche que ce
 * qui l'implémente, et le reste continue de protéger la connexion.
 */
interface Challenge extends Factor
{
    /**
     * Ce qu'il faut donner au navigateur pour qu'il sache répondre, ou nul quand un champ de
     * saisie suffit.
     *
     * La chaîne est opaque pour tout ce qui la transporte : l'écran la passe au comportement
     * du navigateur sans la lire, et seul le mécanisme qui l'a produite sait ce qu'elle dit.
     * C'est ce qui permet à une clé de sécurité et à un code à six chiffres de partager un
     * écran sans que celui-ci connaisse ni l'une ni l'autre.
     *
     * Appelée à chaque affichage : une demande n'est valable qu'une fois, et la rejouer serait
     * précisément ce qu'elle existe pour empêcher.
     */
    public function question(string $userIdentifier): ?string;

    /**
     * La réponse est-elle celle qu'on attendait de ce compte.
     *
     * Rend faux pour une réponse vide, pour un compte qui n'a pas ce moyen, et pour tout ce qui
     * ne se vérifie pas — jamais d'exception : une réponse fausse est le cas courant, pas un
     * incident.
     */
    public function accepts(string $userIdentifier, string $answer): bool;
}
