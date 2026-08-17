<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenMoment;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ReproveController;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ReturnPath;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * L'écran qui redemande un moyen, importé quand l'application sait rendre une page et qu'un
 * paquet d'autorisation peut exiger une preuve récente.
 *
 * Il reçoit les moyens qui savent se faire redemander, pas les mécanismes : ce qui ne sait pas
 * répondre à volonté continue de protéger la connexion sans figurer ici.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(ReproveController::class)
            ->args([
                tagged_iterator('authentication_policy.challenge'),
                service(Visitor::class),
                service(ProvenMoment::class),
                service(ReturnPath::class),
                service(Environment::class),
                service(CsrfTokenManagerInterface::class)->nullOnInvalid(),
                param(Parameter::TEMPLATE.'.reprove'),
                param(Parameter::TEMPLATE.'.layout'),
            ])
            ->tag('controller.service_arguments')
            ->tag('authentication_policy.screen', ['key' => 'reprove'])
            ->public()
    ;
};
