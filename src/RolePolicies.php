<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce que l'administration a posé sur les rôles.
 *
 * Le paquet ne stocke rien et ne saura jamais où c'est rangé : une table, un fichier, un
 * annuaire distant. Il ne connaît pas davantage votre modèle de rôles — il passe les noms que
 * le jeton de sécurité porte, et rien d'autre.
 *
 * Une valeur rendue ne peut que resserrer ce que la configuration a posé. Il n'existe aucun
 * moyen pour une implémentation de desserrer quoi que ce soit : ce n'est pas une consigne, la
 * résolution ne sait pas le faire.
 */
interface RolePolicies
{
    /**
     * Les valeurs posées sur **un** rôle, indexées par l'identité d'un réglage —
     * {@see Setting::value}.
     *
     * Un rôle à la fois, et c'est la seule signature qui tienne la promesse. Quelqu'un qui en
     * porte trois ferait autrement arbitrer l'implémentation entre trois valeurs d'un même
     * réglage — c'est-à-dire décider, hors de toute garantie, laquelle l'emporte. Ici la
     * question ne se pose pas : chaque rôle répond pour lui, et {@see PolicyResolver} garde la
     * plus stricte, quel que soit l'ordre.
     *
     * Un réglage absent laisse parler le niveau suivant. Rendre la valeur la plus permissive
     * n'est pas équivalent : ce serait décider de ne rien exiger, ce qui est une décision.
     *
     * @param string $role un nom tel que le jeton le porte, `ROLE_` compris
     *
     * @return array<string, bool|int>
     */
    public function valuesFor(string $role): array;
}
