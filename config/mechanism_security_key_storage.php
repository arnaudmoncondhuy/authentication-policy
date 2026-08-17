<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\DbalSecurityKeys;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le rangement du paquet, importé seulement quand l'application n'en nomme pas d'autre.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(DbalSecurityKeys::class)
            ->args([service(Tables::class)])
            ->tag('authentication_policy.forgettable')

        ->alias(Parameter::STORE.'.security_key', DbalSecurityKeys::class)
    ;
};
