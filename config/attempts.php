<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\AttemptLimiter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\RateLimiter\RateLimiterFactory;
use Symfony\Component\RateLimiter\Storage\CacheStorage;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le compte des réponses fausses devant un moyen.
 *
 * Importé dès qu'un écran de ce paquet accepte un secret. Le pare-feu de Symfony ne limite que
 * le formulaire de connexion : ce qui se passe sur ces écrans-là n'est compté nulle part
 * ailleurs.
 *
 * Le compteur vit dans le cache de l'application plutôt que dans une table à nous : il n'a
 * aucune valeur au-delà de sa fenêtre, et le perdre au redémarrage n'ouvre rien de plus que
 * d'attendre cette fenêtre.
 */
return static function (ContainerConfigurator $container): void {
    $container->services()
        ->set('authentication_policy.attempts.storage', CacheStorage::class)
            ->args([service('cache.app')])

        ->set('authentication_policy.attempts.limiters', RateLimiterFactory::class)
            ->args([
                [
                    'id' => 'authentication_policy_attempts',
                    // Glissante plutôt que fixe : une fenêtre fixe se recharge d'un coup, et
                    // laisse tirer deux pleines rafales à sa frontière.
                    'policy' => 'sliding_window',
                    'limit' => param(Parameter::ATTEMPTS_MAX),
                    'interval' => param(Parameter::ATTEMPTS_INTERVAL),
                ],
                service('authentication_policy.attempts.storage'),
            ])

        ->set(AttemptLimiter::class)
            ->args([service('authentication_policy.attempts.limiters')])
            ->public()
    ;
};
