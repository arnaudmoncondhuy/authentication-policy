<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ExitDoor;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKey;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKeyAtLogin;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * L'étape de connexion du mécanisme, importée quand l'application sait poser un second facteur.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(SecurityKeyAtLogin::class)
            ->args([
                service(SecurityKey::class),
                service(Perimeter::class),
                service(ExitDoor::class),
                service(TokenStorageInterface::class),
                service(RequestStack::class),
                service(Environment::class),
                param(Parameter::TEMPLATE.'.login_security_key'),
                param(Parameter::TEMPLATE.'.login_layout'),
            ])
            ->tag('scheb_two_factor.provider', ['alias' => 'security_key'])
    ;
};
