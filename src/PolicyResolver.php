<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Ce qui est exigé de quelqu'un, une fois les trois niveaux entendus.
 *
 * L'ordre ne se configure pas : la configuration parle, puis les rôles, puis la personne.
 * Chaque niveau ne peut que resserrer ce que le précédent a laissé, et cette garantie n'est pas
 * un contrôle qu'on pourrait retirer — elle tient à {@see Kind::restrict()}, qui ne sait rendre
 * que la plus stricte de deux valeurs. Il n'existe aucun chemin de code par lequel un rôle
 * desserre le plafond, ni une personne son rôle.
 *
 * Un niveau non délégué n'est pas interrogé, même si une valeur traîne pour lui : elle rejoint
 * {@see Decisions::ignored()}, où elle reste visible.
 *
 * Le contrat ne connaît ni requête, ni session, ni jeton : il reçoit une identité et des noms
 * de rôles. C'est ce qui le rend appelable depuis une commande, un test ou une tâche
 * planifiée — et ce qui interdit à une valeur venue de la requête d'y entrer.
 */
final readonly class PolicyResolver
{
    public function __construct(
        private Policy $policy,
        private ?RolePolicies $roles = null,
        private ?UserPreferences $preferences = null,
    ) {
    }

    /**
     * @param string $userIdentifier ce que le jeton de sécurité désigne comme identité
     * @param string ...$roleNames   les rôles que ce même jeton porte
     *
     * @throws UnknownSetting      si un stockage rend une identité de réglage inconnue
     * @throws InvalidSettingValue si un stockage rend une valeur du mauvais type
     */
    public function decideFor(string $userIdentifier, string ...$roleNames): Decisions
    {
        // Chaque niveau porte une liste de sources : autant que de rôles pour le premier, une
        // seule pour le second. C'est ici que se joue l'indépendance à l'ordre — les sources
        // d'un même niveau se replient entre elles avant tout le reste.
        $stored = [
            Decider::Role->value => array_map(
                fn (string $role): array => $this->normalize($this->roles?->valuesFor($role) ?? []),
                $roleNames,
            ),
            Decider::User->value => [$this->normalize($this->preferences?->valuesFor($userIdentifier) ?? [])],
        ];

        $decisions = [];
        $ignored = [];

        foreach (Setting::all() as $setting) {
            $rule = $this->policy->ruleFor($setting);
            $value = $rule->ceiling;
            $decidedBy = Decider::Hardcoded;

            foreach (Decider::delegatable() as $decider) {
                $ignoredHere = false;

                foreach ($stored[$decider->value] ?? [] as $source) {
                    $proposed = $source[$setting->value] ?? null;

                    if (null === $proposed) {
                        continue;
                    }

                    if (!$rule->delegatesTo($decider)) {
                        // Une seule fois par niveau : deux rôles porteurs de la même valeur
                        // écartée sont une même préférence sans effet, pas deux.
                        if (!$ignoredHere) {
                            $ignored[] = new IgnoredValue($setting, $decider, $proposed);
                            $ignoredHere = true;
                        }

                        continue;
                    }

                    $restricted = $setting->kind()->restrict($value, $proposed);

                    if ($restricted !== $value) {
                        $decidedBy = $decider;
                        $value = $restricted;
                    }
                }
            }

            $decisions[] = new Decision(
                $setting,
                $value,
                $decidedBy,
                !$rule->delegatesTo(Decider::User) || $setting->kind()->isStrictest($value),
            );
        }

        return new Decisions($decisions, $ignored);
    }

    /**
     * Vérifie qu'un stockage ne rend que des réglages connus, et des valeurs de leur nature.
     *
     * Le refus est immédiat et bruyant. La source de ces valeurs est une base que le paquet ne
     * gouverne pas : les convertir ou les écarter en silence reviendrait à laisser une session
     * dépendre d'une ligne que personne ne relit jamais.
     *
     * @param array<string, bool|int> $values
     *
     * @return array<string, bool|int>
     *
     * @throws UnknownSetting
     * @throws InvalidSettingValue
     */
    private function normalize(array $values): array
    {
        foreach ($values as $id => $value) {
            Setting::ofId($id)->kind()->refuseForeignValue($value);
        }

        return $values;
    }
}
