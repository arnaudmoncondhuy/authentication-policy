<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\SecurityScreenController;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
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
                service(TokenStorageInterface::class),
                service(Environment::class),
                '@AuthenticationPolicy/security.html.twig',
                param(Parameter::LAYOUT),
            ])
            ->tag('controller.service_arguments')
            ->public()
    ;
};
