<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\BackupCodesController;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * L'écran des codes de secours, importé quand le mécanisme est allumé et que l'application
 * sait rendre une page.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(BackupCodesController::class)
            ->args([
                service(BackupCodes::class),
                service(Factors::class),
                service(TokenStorageInterface::class),
                service(Environment::class),
                service(UrlGeneratorInterface::class),
                service(CsrfTokenManagerInterface::class)->nullOnInvalid(),
                '@AuthenticationPolicy/backup_codes.html.twig',
                param(Parameter::LAYOUT),
            ])
            ->tag('controller.service_arguments')
            ->public()
    ;
};
