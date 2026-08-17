<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\DoctorCommand;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ForgetCommand;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\PolicyCommand;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Storage\Oblivion;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Importé partout où symfony/console est installé, pare-feu ou non : afficher la politique ne
 * demande ni requête ni compte connecté.
 *
 * Le docteur reçoit les stockages en `nullOnInvalid` parce que leur absence est justement ce
 * qu'il rapporte. Les recevoir autrement le rendrait impossible à construire dans l'application
 * qui en a le plus besoin.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(PolicyCommand::class)
            ->args([
                service(Policy::class),
                service(RolePolicies::class)->nullOnInvalid(),
            ])
            ->tag('console.command')

        // L'oubli n'existe que si le paquet range quelque chose ; la commande le dit plutôt que
        // de disparaître, faute de quoi son absence passerait pour un oubli de sa part.
        ->set(ForgetCommand::class)
            ->args([service(Oblivion::class)->nullOnInvalid()])
            ->tag('console.command')

        ->set(DoctorCommand::class)
            ->args([
                service(Policy::class),
                param(Parameter::FINDINGS),
                param(Parameter::ENROLLMENT_PATH),
                service(RolePolicies::class)->nullOnInvalid(),
                service(UserPreferences::class)->nullOnInvalid(),
                param(Parameter::FIREWALLS),
                param(Parameter::MECHANISMS),
                param(Parameter::AUTO_SETUP),
                // Nul quand le pont n'est pas monté, et c'est justement ce que la commande
                // rapporte : le recevoir autrement la rendrait impossible à construire là où
                // elle a le plus à dire.
                service(ProofOfIdentity::class)->nullOnInvalid(),
                param(Parameter::PROOF_FRESHNESS),
            ])
            ->tag('console.command')
    ;
};
