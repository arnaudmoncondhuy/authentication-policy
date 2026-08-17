<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Un moyen de prouver qui l'on est, tel que le reste du paquet le voit.
 *
 * Le paquet ne sait pas ce qu'est un code à six chiffres, une clé ou un code de secours : il
 * sait qu'un compte en possède un certain nombre, et c'est tout ce qu'il lui faut pour exiger,
 * compter et refuser. Un mécanisme nouveau s'ajoute en implémentant ce contrat ; rien de ce qui
 * est écrit ici ne bouge.
 */
interface Factor
{
    /**
     * Le nom sous lequel ce moyen se désigne — `backup_codes`, `totp`, `security_key`.
     *
     * Il survit en configuration et dans les écrans : le changer revient à faire disparaître le
     * moyen aux yeux de tout ce qui le nommait.
     *
     * @return non-empty-string
     */
    public function name(): string;

    /**
     * Combien d'exemplaires de ce moyen ce compte a posés.
     *
     * Un compte sans rien répond zéro. Un mécanisme qui ne se pose qu'une fois répond zéro ou
     * un ; des codes de secours répondent ce qu'il en reste, car ils s'épuisent.
     */
    public function countFor(string $userIdentifier): int;

    /**
     * La route où l'on pose et retire ce moyen.
     *
     * C'est ce qui permet à l'écran de sécurité de mener quelque part : un moyen qu'on ne
     * saurait pas atteindre n'y figurerait que pour informer, ce qui n'aide personne.
     *
     * @return non-empty-string
     */
    public function manageAt(): string;

    /**
     * Ce moyen sert-il de recours quand tous les autres sont perdus.
     *
     * Un compte qui n'en a aucun tient debout tant que rien ne casse. L'écran de sécurité le
     * dit, sans avoir à connaître un seul mécanisme par son nom.
     */
    public function isRecovery(): bool;
}
