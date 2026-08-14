<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si la politique délègue à un niveau que rien ne stocke.
 *
 * C'est la deuxième garantie du paquet. Sans elle, une configuration peut annoncer qu'une
 * personne choisit la durée de sa session alors qu'aucune classe ne sait où ce choix se range :
 * l'écran de profil affiche un champ, quelqu'un le règle, et rien n'est enregistré. Le réglage
 * paraît tenu, il ne l'est pas — et c'est la seule des trois fautes qui ne se voit jamais à
 * l'usage, puisque la valeur retombe simplement sur celle du niveau précédent.
 *
 * La faute se constate sans démarrer l'application : la délégation est écrite dans la
 * configuration, le stockage est un service, et les deux sont là au moment de compiler.
 */
final readonly class RefuseDelegationWithoutStorePass implements CompilerPassInterface
{
    /**
     * Le contrat que chaque niveau délégable réclame.
     *
     * @var array<string, class-string>
     */
    private const array STORES = [
        Decider::Role->value => RolePolicies::class,
        Decider::User->value => UserPreferences::class,
    ];

    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter(Parameter::RULES)) {
            return;
        }

        /** @var array<string, array{ceiling: bool|int, delegated_to: list<string>}> $rules */
        $rules = $container->getParameter(Parameter::RULES);
        $policy = PolicyFactory::fromArray($rules);

        foreach (Decider::delegatable() as $decider) {
            $delegated = $policy->delegatedTo($decider);

            if ([] === $delegated) {
                continue;
            }

            $store = self::STORES[$decider->value] ?? null;

            if (null === $store || $container->has($store)) {
                continue;
            }

            throw new LogicException(\sprintf("La politique délègue ces réglages — %s décide — mais aucun service n'implémente %s :\n  - %s\nCes choix n'auraient nulle part où se ranger : implémenter le contrat, ou retirer la délégation.", $decider->label(), $store, implode("\n  - ", array_map(static fn (Setting $setting): string => $setting->value, $delegated))));
        }
    }
}
