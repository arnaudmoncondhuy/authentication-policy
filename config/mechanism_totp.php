<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\QrCode;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\Totp;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp\TotpSecrets;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le mécanisme du code à six chiffres, importé seulement quand l'application l'allume.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(QrCode::class)

        ->set(Totp::class)
            ->args([
                service(Parameter::STORE.'.totp'),
                service(Factors::class),
                service(ClockInterface::class),
                param(Parameter::MECHANISM.'.totp.issuer'),
                param(Parameter::MECHANISM.'.totp.server_name'),
                param(Parameter::MECHANISM.'.totp.digits'),
                param(Parameter::MECHANISM.'.totp.period'),
                param(Parameter::MECHANISM.'.totp.algorithm'),
                param(Parameter::MECHANISM.'.totp.leeway'),
            ])
            ->tag('authentication_policy.factor')
            ->public()

        ->alias(TotpSecrets::class, Parameter::STORE.'.totp')
    ;
};
