<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;

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

    private function __construct()
    {
    }
}
