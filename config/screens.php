<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SecurityScreenController;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * L'écran de sécurité, importé quand l'application sait rendre une page.
 *
 * Il ne dépend d'aucun mécanisme : il montre ce qui est installé, fût-ce rien, et c'est
 * justement quand il n'y a rien qu'il a le plus à dire.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(SecurityScreenController::class)
            ->args([
                service(Factors::class),
                service(Visitor::class),
                service(Environment::class),
                param(Parameter::TEMPLATE.'.security'),
                param(Parameter::TEMPLATE.'.layout'),
            ])
            ->tag('controller.service_arguments')
            ->tag('authentication_policy.screen', ['key' => 'security'])
            ->public()
    ;
};
