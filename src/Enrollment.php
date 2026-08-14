<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Si quelqu'un a posé ce que la politique exige de lui.
 *
 * Le paquet ne sait pas ce qu'« avoir posé son second facteur » veut dire chez vous : un secret
 * partagé enregistré, une clé enrôlée, des codes de secours imprimés. Il pose la question, le
 * projet répond.
 *
 * De cette réponse dépend le verrou : tant qu'elle est fausse pour quelqu'un dont la politique
 * exige le second facteur, aucune surface ne lui répond, à l'exception de celles qui portent
 * {@see DuringEnrollment}. Une implémentation qui rendrait vrai par facilité ouvrirait tout, et
 * rien ne le signalerait — c'est le point le plus sensible que ce contrat confie au projet.
 */
interface Enrollment
{
    /**
     * @param string $userIdentifier ce que le jeton de sécurité désigne comme identité, et
     *                               jamais une valeur venue de la requête
     */
    public function isCompleteFor(string $userIdentifier): bool;
}
