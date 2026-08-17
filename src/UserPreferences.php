<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce qu'une personne a choisi pour elle-même.
 *
 * Ce niveau est ce qui prouve que le paquet ne décide rien : une politique qui n'accepterait
 * que le fichier de configuration déciderait à la place du projet, et l'écran de profil
 * n'aurait plus qu'à mentir.
 *
 * Comme le précédent, il ne peut que resserrer. Quelqu'un peut exiger de lui-même un second
 * facteur que son rôle n'exige pas, ou écourter sa session ; il ne peut pas s'accorder ce que
 * son rôle lui refuse.
 */
interface UserPreferences
{
    /**
     * Les valeurs choisies par cette personne, indexées par l'identité d'un réglage —
     * {@see Setting::value}.
     *
     * Un réglage absent laisse la décision au niveau précédent, ce qui est le cas de tout
     * compte n'ayant jamais ouvert son profil.
     *
     * @param string $userIdentifier ce que le jeton de sécurité désigne comme identité, et
     *                               jamais une valeur venue de la requête
     *
     * @return array<string, bool|int>
     */
    public function valuesFor(string $userIdentifier): array;

    /**
     * Retient ce qu'une personne a choisi pour elle-même.
     *
     * Ce qui est retenu n'est pas ce qui s'applique : un choix plus large que le plafond reste
     * rangé tel quel, et la résolution le ramène au plafond. C'est ce qui permet de desserrer la
     * politique plus tard sans avoir à redemander à chacun ce qu'il voulait.
     *
     * @param array<string,bool|int|null> $values indexé par le nom du réglage ; null efface le choix
     */
    public function remember(string $userIdentifier, array $values): void;
}
