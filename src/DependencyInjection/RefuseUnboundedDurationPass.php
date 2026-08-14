<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Kind;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/**
 * Refuse de compiler le conteneur si une durée est déléguée sans plafond.
 *
 * C'est la troisième garantie du paquet, et c'est la moitié que la résolution ne peut pas
 * tenir seule. Le repliement garantit qu'un niveau ne desserre jamais le précédent ; encore
 * faut-il qu'il y ait quelque chose à resserrer. Une durée sans plafond part de « aucune
 * limite », et un rôle qui pose trente jours devient alors la politique — sans rien enfreindre.
 *
 * Le contrôle ne porte que sur les durées : une exigence part de « non exigé » et une
 * permission de « autorisé », deux points de départ qui veulent dire quelque chose. « Aucune
 * limite » n'en est pas un.
 */
final readonly class RefuseUnboundedDurationPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasParameter(Parameter::RULES)) {
            return;
        }

        /** @var array<string, array{ceiling: bool|int, delegated_to: list<string>}> $rules */
        $rules = $container->getParameter(Parameter::RULES);
        $policy = PolicyFactory::fromArray($rules);

        $unbounded = [];

        foreach (Setting::all() as $setting) {
            $rule = $policy->ruleFor($setting);

            if (Kind::Duration !== $setting->kind() || [] === $rule->delegatedTo) {
                continue;
            }

            if (\PHP_INT_MAX === $rule->ceiling) {
                $unbounded[] = $setting->value;
            }
        }

        if ([] !== $unbounded) {
            throw new LogicException(\sprintf("Ces durées sont déléguées sans plafond, et le niveau délégué deviendrait donc la politique :\n  - %s\n".'Poser un plafond, ou retirer la délégation.', implode("\n  - ", $unbounded)));
        }
    }
}
