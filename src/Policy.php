<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * La politique telle que la configuration la déclare : une règle par réglage.
 *
 * Elle ne connaît personne. Ce qu'elle sait, c'est ce qui est permis à qui que ce soit et à qui
 * la décision est déléguée ensuite — {@see PolicyResolver} y ajoute les rôles d'une personne et
 * ses préférences.
 *
 * Un réglage absent de la configuration reçoit sa règle la plus permissive : le paquet
 * s'installe sans rien écrire, et n'impose rien tant qu'on ne lui a rien demandé.
 */
final readonly class Policy
{
    /** @var array<string, Rule> */
    private array $rules;

    /** @param iterable<Rule> $rules */
    public function __construct(iterable $rules = [])
    {
        $byId = [];

        foreach ($rules as $rule) {
            $byId[$rule->setting->value] = $rule;
        }

        $this->rules = $byId;
    }

    public function ruleFor(Setting $setting): Rule
    {
        return $this->rules[$setting->value] ?? Rule::unset($setting);
    }

    /**
     * Toutes les règles, y compris celles que la configuration ne mentionne pas. C'est ce
     * qu'affiche `authentication-policy:policy` : un réglage tu n'est pas un réglage absent,
     * c'est un réglage laissé ouvert.
     *
     * @return list<Rule>
     */
    public function all(): array
    {
        return array_map($this->ruleFor(...), Setting::all());
    }

    /**
     * Les réglages qui délèguent à ce niveau.
     *
     * C'est ce que lisent les passes de compilation : déléguer suppose un stockage, et
     * l'absence de stockage se constate sans démarrer l'application.
     *
     * @return list<Setting>
     */
    public function delegatedTo(Decider $decider): array
    {
        return array_values(array_filter(
            Setting::all(),
            fn (Setting $setting): bool => $this->ruleFor($setting)->delegatesTo($decider),
        ));
    }

    /** Vrai quand la politique peut exiger ce réglage de quelqu'un, par quelque niveau que ce soit. */
    public function canRequire(Setting $setting): bool
    {
        $rule = $this->ruleFor($setting);

        return $setting->kind()->isStrictest($rule->ceiling) || [] !== $rule->delegatedTo;
    }
}
