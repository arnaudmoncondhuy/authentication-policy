<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Storage;

/**
 * Un rangement qui sait tout oublier d'un compte.
 *
 * Le paquet range sous un identifiant, jamais sous une clé étrangère : il ne connaît ni la
 * table des comptes de l'application, ni sa clé primaire, et la base ne peut donc rien effacer
 * en cascade. Ce qu'un compte a posé lui survit, et un compte recréé sous la même adresse en
 * hériterait.
 *
 * Chaque rangement porte donc de quoi s'effacer, et {@see Oblivion} les appelle tous.
 *
 * @internal ce contrat sert entre rangements du paquet ; une application n'a rien à en faire
 */
interface Forgettable
{
    /**
     * @param string $userIdentifier ce que le jeton de sécurité désigne comme identité, et
     *                               jamais une valeur venue de la requête
     */
    public function forgetEverythingOf(string $userIdentifier): void;
}
