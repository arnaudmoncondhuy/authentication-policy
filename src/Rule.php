<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce que la configuration dit d'un réglage : sa borne, et qui a le droit d'en parler ensuite.
 *
 * La borne n'est pas une valeur par défaut qu'on remplace, c'est le point de départ d'un
 * repliement qui ne sait que resserrer. Une politique qui pose huit heures d'inactivité et
 * délègue au rôle ne peut pas produire trente jours : il n'existe aucun chemin de code qui
 * remonte.
 */
final readonly class Rule
{
    /**
     * @param list<Decider> $delegatedTo les niveaux autorisés à resserrer, dans un ordre
     *                                   indifférent : c'est {@see Decider::delegatable()} qui
     *                                   fixe celui où ils s'expriment
     *
     * @throws InvalidSettingValue si la borne n'est pas du type du réglage
     */
    public function __construct(
        public Setting $setting,
        public bool|int $ceiling,
        public array $delegatedTo = [],
    ) {
        $setting->kind()->refuseForeignValue($ceiling);
    }

    /**
     * La règle d'un réglage dont la configuration ne dit rien : la borne la plus permissive,
     * et personne d'autre à qui parler.
     */
    public static function unset(Setting $setting): self
    {
        return new self($setting, $setting->kind()->loosest());
    }

    public function delegatesTo(Decider $decider): bool
    {
        return \in_array($decider, $this->delegatedTo, true);
    }

    /**
     * Vrai quand la borne laisse encore quelque chose à décider.
     *
     * Déléguer un réglage déjà au plus strict n'est pas une faute — c'est une case qui
     * n'aura jamais d'effet, et `authentication-policy:policy` la montre comme telle.
     */
    public function leavesRoom(): bool
    {
        return !$this->setting->kind()->isStrictest($this->ceiling);
    }
}
