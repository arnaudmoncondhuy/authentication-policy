<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factor;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * Le compte des moyens, tous mécanismes confondus.
 *
 * Importé dès qu'un mécanisme est allumé : sans lui, chacun retirerait son dernier exemplaire
 * sans savoir que le compte n'a rien d'autre.
 */
return static function (Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator $container): void {
    $container->services()
        ->instanceof(Factor::class)
            ->tag('authentication_policy.factor')

        ->set(Factors::class)
            ->args([
                tagged_iterator('authentication_policy.factor'),
                // Le refus de retirer le dernier moyen n'a de sens que si quelque chose l'exige.
                // Une application qui n'exige rien laisse chacun retirer ce qu'il veut.
                param(Parameter::TWO_FACTOR_REQUIRABLE),
            ])
        ->public()
    ;
};
