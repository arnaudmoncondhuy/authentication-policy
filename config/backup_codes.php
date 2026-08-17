<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\BackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\BackupCodesController;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\DbalBackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use Doctrine\DBAL\Connection;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le mécanisme des codes de secours, importé seulement quand l'application les allume.
 *
 * Le rangement par défaut réclame une base de données. Une application qui range ailleurs nomme
 * son service dans la configuration : celui du paquet n'est alors même pas décrit.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services
        ->set(BackupCodes::class)
            ->args([service(BackupCodeStore::class), service(Factors::class)])
            ->tag('authentication_policy.factor')
            ->public()
    ;

    if (class_exists(Environment::class)) {
        $services
            ->set(BackupCodesController::class)
                ->args([
                    service(BackupCodes::class),
                    service(Factors::class),
                    service(TokenStorageInterface::class),
                    service(Environment::class),
                    service(UrlGeneratorInterface::class),
                    service(CsrfTokenManagerInterface::class)->nullOnInvalid(),
                    param(Parameter::BACKUP_CODES_TEMPLATE),
                    param(Parameter::BACKUP_CODES_LAYOUT),
                ])
                ->tag('controller.service_arguments')
                ->public()
        ;
    }

    if (class_exists(Connection::class)) {
        $services
            ->set(DbalBackupCodeStore::class)
                ->args([service(Connection::class), param(Parameter::BACKUP_CODES_AUTO_SETUP)])
            ->alias(BackupCodeStore::class, DbalBackupCodeStore::class)
        ;
    }
};
