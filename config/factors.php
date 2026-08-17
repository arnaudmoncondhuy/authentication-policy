<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\Authorization\ProofOfIdentity;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;
use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * Le compte des moyens, tous mécanismes confondus.
 *
 * Importé toujours : il vaut même quand aucun mécanisme n'est allumé, et c'est alors lui qui
 * répond zéro au verrou.
 *
 * Chaque mécanisme se marque dans son propre fichier de services. Rien ne marque un moyen
 * automatiquement : une classe venue d'ailleurs se ferait compter sans que le paquet réponde de
 * sa solidité, et RefuseForeignFactorPass arrête la compilation avant cela.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set(Factors::class)
            ->args([
                tagged_iterator('authentication_policy.factor'),
                // Le refus de retirer le dernier moyen n'a de sens que si quelque chose l'exige.
                // Une application qui n'exige rien laisse chacun retirer ce qu'il veut.
                param(Parameter::TWO_FACTOR_REQUIRABLE),
            ])
            ->public()

        // Qui a le droit de poser ou de retirer un moyen. Le juge des preuves est référencé en
        // « ignore on invalid » : il vient de l'autre paquet, et celui-ci doit continuer de
        // fonctionner sans lui.
        ->set(ProvenEnrollment::class)
            ->args([
                service(Factors::class),
                service(ProofOfIdentity::class)->nullOnInvalid(),
            ])
            ->public()
    ;
};
