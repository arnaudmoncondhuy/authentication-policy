<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Qui a décidé de la valeur qu'un réglage a prise.
 *
 * L'ordre des cas est celui dans lequel ils s'expriment, et il ne se configure pas : le dur
 * parle en premier, puis les rôles, puis la personne. Chacun ne peut que resserrer ce que le
 * précédent a laissé — {@see Kind::restrict()} le tient.
 *
 * Cette identité voyage jusqu'à l'écran de profil. Sans elle, une case grisée n'a pas
 * d'explication, et c'est là que naît la douleur : quelqu'un qui ne comprend pas pourquoi il ne
 * peut pas changer un réglage finit par demander qu'on le lui ouvre.
 */
enum Decider: string
{
    /** Le fichier de configuration. Ne se délègue pas : il est toujours le premier à parler. */
    case Hardcoded = 'hardcoded';

    /** Ce que l'administration a posé sur un rôle. */
    case Role = 'role';

    /** Ce que la personne a choisi pour elle-même. */
    case User = 'user';

    /**
     * Les niveaux qu'une politique peut déléguer, dans l'ordre où ils s'expriment.
     *
     * @return list<self>
     */
    public static function delegatable(): array
    {
        return [self::Role, self::User];
    }

    public function label(): string
    {
        return match ($this) {
            self::Hardcoded => 'la configuration',
            self::Role => 'le rôle',
            self::User => 'la personne',
        };
    }
}
