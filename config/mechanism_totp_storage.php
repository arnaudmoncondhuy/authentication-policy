<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\DbalTotpSecrets;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Tables;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le rangement du paquet, importé seulement quand l'application n'en nomme pas d'autre.
 *
 * Le secret est rangé tel quel — il faut pouvoir le rendre — ce qui est précisément la raison
 * de laisser une application le remplacer par un rangement chiffré.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(DbalTotpSecrets::class)
            ->args([service(Tables::class)])
            ->tag('authentication_policy.forgettable')

        ->alias(Parameter::STORE.'.totp', DbalTotpSecrets::class)
    ;
};
