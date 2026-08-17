<?php

declare(strict_types=1);

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKey;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKeys;
use Psr\Clock\ClockInterface;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Webauthn\AttestationStatement\AttestationStatementSupportManager;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\CeremonyStep\CeremonyStepManager;
use Webauthn\CeremonyStep\CeremonyStepManagerFactory;
use Webauthn\Denormalizer\WebauthnSerializerFactory;

use function Symfony\Component\DependencyInjection\Loader\Configurator\param;
use function Symfony\Component\DependencyInjection\Loader\Configurator\service;

/*
 * Le mécanisme des clés de sécurité, importé seulement quand l'application l'allume.
 *
 * Le sérialiseur et les validateurs sont montés ici, à partir de la seule bibliothèque : le
 * paquet n'exige ni le paquet Symfony de WebAuthn, ni que le sérialiseur du framework soit
 * activé — deux choses qu'une application n'a aucune raison d'installer pour poser une clé.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    $services
        ->set('authentication_policy.security_key.attestations', AttestationStatementSupportManager::class)

        ->set('authentication_policy.security_key.serializer_factory', WebauthnSerializerFactory::class)
            ->args([service('authentication_policy.security_key.attestations')])

        ->set('authentication_policy.security_key.serializer', Symfony\Component\Serializer\SerializerInterface::class)
            ->factory([service('authentication_policy.security_key.serializer_factory'), 'create'])

        // Les origines acceptées en plus de celle de la requête. Vide, l'hôte fait foi — ce qui
        // est le bon défaut : une origine de trop est une porte de trop.
        ->set('authentication_policy.security_key.ceremonies', CeremonyStepManagerFactory::class)
            ->call('setAllowedOrigins', [param(Parameter::MECHANISM.'.security_key.allowed_origins')])

        ->set('authentication_policy.security_key.creation', CeremonyStepManager::class)
            ->factory([service('authentication_policy.security_key.ceremonies'), 'creationCeremony'])

        ->set('authentication_policy.security_key.request', CeremonyStepManager::class)
            ->factory([service('authentication_policy.security_key.ceremonies'), 'requestCeremony'])

        ->set(AuthenticatorAttestationResponseValidator::class)
            ->args([service('authentication_policy.security_key.creation')])

        ->set(AuthenticatorAssertionResponseValidator::class)
            ->args([service('authentication_policy.security_key.request')])

        ->set(SecurityKey::class)
            ->args([
                service(Parameter::STORE.'.security_key'),
                service(Factors::class),
                service('authentication_policy.security_key.serializer'),
                service(AuthenticatorAttestationResponseValidator::class),
                service(AuthenticatorAssertionResponseValidator::class),
                service(ClockInterface::class),
                param(Parameter::MECHANISM.'.security_key.relying_party_name'),
                param(Parameter::MECHANISM.'.security_key.relying_party_id'),
                param(Parameter::MECHANISM.'.security_key.timeout'),
                param(Parameter::MECHANISM.'.security_key.user_verification'),
                param(Parameter::MECHANISM.'.security_key.resident_key'),
                param(Parameter::MECHANISM.'.security_key.label_max_length'),
            ])
            ->tag('authentication_policy.factor')
            ->public()

        ->alias(SecurityKeys::class, Parameter::STORE.'.security_key')
    ;
};
