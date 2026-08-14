<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * La nature d'un réglage, et avec elle le sens de « plus strict ».
 *
 * C'est la pièce qui rend la politique sûre par construction : chaque nature sait replier deux
 * valeurs en gardant la plus stricte, et jamais l'inverse. Un niveau qui parle après un autre
 * ne peut donc que resserrer — un rôle ne desserre pas le plafond, une personne ne desserre pas
 * son rôle. La règle n'est pas contrôlée après coup, elle est indisponible.
 *
 * Trois natures, parce que « plus strict » n'a pas le même sens selon ce qu'on règle :
 *
 * - une **exigence** est plus stricte quand elle est vraie — exiger le second facteur ;
 * - une **permission** est plus stricte quand elle est fausse — interdire l'appareil de
 *   confiance ;
 * - une **durée** est plus stricte quand elle est courte.
 *
 * Confondre les deux premières inverserait la garantie exactement là où elle compte : une
 * permission repliée comme une exigence laisserait un rôle rendre possible ce que le plafond
 * interdit.
 */
enum Kind
{
    /** Vrai = exigé. Ce qu'on impose. */
    case Requirement;

    /** Vrai = autorisé. Ce qu'on tolère. */
    case Permission;

    /** Un nombre de secondes. Zéro n'a pas de sens : une durée nulle ferme la porte à tous. */
    case Duration;

    /**
     * La valeur la plus permissive de cette nature, d'où part le repliement.
     *
     * Pour une durée, l'absence de plafond signifie « aucune limite » ; c'est justement ce
     * qu'une passe de compilation interdit de déléguer, faute de quoi un rôle partirait de là.
     */
    public function loosest(): bool|int
    {
        return match ($this) {
            self::Requirement => false,
            self::Permission => true,
            self::Duration => \PHP_INT_MAX,
        };
    }

    /**
     * Replie deux valeurs en gardant la plus stricte.
     *
     * L'opération est commutative et associative : l'ordre dans lequel plusieurs rôles
     * s'expriment ne change pas le résultat. C'est ce qui permet à une personne d'en porter
     * trois sans que le hasard de leur rangement décide de sa session.
     *
     * @throws InvalidSettingValue si une valeur n'est pas du type de cette nature
     */
    public function restrict(bool|int $current, bool|int $proposed): bool|int
    {
        $this->refuseForeignValue($current);
        $this->refuseForeignValue($proposed);

        return match ($this) {
            self::Requirement => $current || $proposed,
            self::Permission => $current && $proposed,
            self::Duration => min($current, $proposed),
        };
    }

    /**
     * Vrai quand plus rien ne peut resserrer davantage.
     *
     * Une durée n'atteint jamais ce point : on peut toujours écourter. C'est ce qui distingue,
     * sur un écran de profil, la case grise « imposé par votre rôle » du champ encore ouvert.
     */
    public function isStrictest(bool|int $value): bool
    {
        return match ($this) {
            self::Requirement => true === $value,
            self::Permission => false === $value,
            self::Duration => false,
        };
    }

    /** @throws InvalidSettingValue */
    public function refuseForeignValue(mixed $value): void
    {
        $expected = match ($this) {
            self::Requirement, self::Permission => \is_bool($value),
            self::Duration => \is_int($value) && $value > 0,
        };

        if (!$expected) {
            throw new InvalidSettingValue(\sprintf('Un réglage de nature %s attend %s, et non %s.', $this->name, self::Duration === $this ? 'un nombre de secondes strictement positif' : 'un booléen', get_debug_type($value)));
        }
    }
}
