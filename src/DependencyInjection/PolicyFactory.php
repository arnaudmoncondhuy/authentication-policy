<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\InvalidSettingValue;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\UnknownSetting;

/**
 * Rebâtit la politique depuis ce que le conteneur sait porter.
 *
 * Un conteneur compilé ne conserve que des valeurs simples : la politique y voyage en tableau,
 * et redevient un objet ici — pour le service que les applications injectent comme pour les
 * passes, qui n'ont que le tableau sous la main.
 *
 * Vit sous `DependencyInjection/` et non dans le contrat : la forme du tableau est celle de la
 * configuration, et le contrat n'a pas à connaître la façon dont on l'écrit.
 */
final class PolicyFactory
{
    /**
     * Une borne absente vaut « la plus permissive ». C'est ce qui rend la faute exprimable :
     * déléguer une durée en oubliant son plafond est le geste que
     * {@see RefuseUnboundedDurationPass} refuse, et il faut donc pouvoir l'écrire.
     *
     * @param array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules
     */
    public static function fromArray(array $rules): Policy
    {
        $built = [];

        foreach ($rules as $id => $rule) {
            $setting = Setting::ofId($id);

            $built[] = new Rule(
                $setting,
                $rule['ceiling'] ?? $setting->kind()->loosest(),
                array_map(Decider::from(...), $rule['delegated_to'] ?? []),
            );
        }

        return new Policy($built);
    }

    /**
     * Valide et normalise ce que la configuration pose sur les rôles.
     *
     * Le contrôle a lieu ici, à la compilation, et pas à la lecture : un réglage mal écrit sur
     * un rôle ne se manifesterait autrement que sur le compte de qui le porte, en retombant
     * silencieusement sur le niveau précédent.
     *
     * @param array<string, mixed> $policies
     *
     * @return array<string, array<string, bool|int>>
     */
    public static function rolePoliciesFromArray(array $policies): array
    {
        $built = [];

        foreach ($policies as $role => $values) {
            if (!\is_array($values)) {
                throw new \InvalidArgumentException(\sprintf('Le rôle « %s » doit poser une liste de réglages.', $role));
            }

            $built[$role] = [];

            foreach ($values as $id => $value) {
                try {
                    $setting = Setting::ofId((string) $id);
                    $setting->kind()->refuseForeignValue($value);
                } catch (UnknownSetting|InvalidSettingValue $refusal) {
                    throw new \InvalidArgumentException(\sprintf('Le rôle « %s » pose « %s » : %s', $role, $id, $refusal->getMessage()), previous: $refusal);
                }

                /* @var bool|int $value */
                $built[$role][$setting->value] = $value;
            }
        }

        return $built;
    }

    private function __construct()
    {
    }
}
