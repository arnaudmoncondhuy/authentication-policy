<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\PolicyRoutes;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_locator;

/*
 * Le chargeur de routes du paquet.
 *
 * L'application l'invoque d'une ligne, et c'est elle qui décide alors sous quels chemins les
 * écrans vivent :
 *
 *     authentication_policy:
 *         resource: .
 *         type: authentication_policy
 *
 * Un localisateur plutôt qu'un itérateur : lire le nom des écrans ne doit pas les construire,
 * car chacun réclame de quoi fabriquer des adresses — donc le routeur, donc ce chargeur.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(PolicyRoutes::class)
            ->args([
                tagged_locator('authentication_policy.screen', 'key'),
                param(Parameter::ROUTES),
                param(Parameter::LOGIN_STEP),
            ])
            ->tag('routing.loader')
    ;
};
