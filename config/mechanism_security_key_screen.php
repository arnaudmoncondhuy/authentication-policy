<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKey;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKeyController;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * L'écran du mécanisme. La marque « screen » porte la clé sous laquelle son chemin se configure
 * et sous laquelle sa route se nomme.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(SecurityKeyController::class)
            ->args([
                service(SecurityKey::class),
                service(Factors::class),
                service(ProvenEnrollment::class),
                service(Visitor::class),
                service(Environment::class),
                service(UrlGeneratorInterface::class),
                service(CsrfTokenManagerInterface::class)->nullOnInvalid(),
                param(Parameter::TEMPLATE.'.security_key'),
                param(Parameter::TEMPLATE.'.layout'),
            ])
            ->tag('controller.service_arguments')
            ->tag('authentication_policy.screen', ['key' => 'security_key'])
            ->public()
    ;
};
