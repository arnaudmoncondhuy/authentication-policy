<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

use ArnaudMoncondhuy\AuthenticationPolicy\Factor;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use Cose\Algorithms;
use Psr\Clock\ClockInterface;
use Symfony\Component\HttpFoundation\Session\SessionInterface;
use Symfony\Component\Serializer\Normalizer\AbstractObjectNormalizer;
use Symfony\Component\Serializer\SerializerInterface;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAssertionResponseValidator;
use Webauthn\AuthenticatorAttestationResponse;
use Webauthn\AuthenticatorAttestationResponseValidator;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredential;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Les clés de sécurité : clé physique, empreinte, visage, code de l'appareil.
 *
 * Une seule norme derrière ces quatre mots — l'appareil garde une partie secrète qui ne le
 * quitte jamais, et signe un défi tiré au hasard. Rien de réutilisable ne circule, et une clé
 * posée sur un site ne prouve rien sur un autre.
 *
 * Le défi vit dans la session le temps d'un aller-retour, et pas au-delà : une réponse arrivée
 * sans que rien n'ait été demandé ne prouve rien.
 */
final readonly class SecurityKey implements Factor
{
    public const string NAME = 'security_key';

    private const string ENROLMENT_KEY = '_authentication_policy.security_key.enrolment';
    private const string CHALLENGE_KEY = '_authentication_policy.security_key.challenge';

    public function __construct(
        private SecurityKeys $keys,
        private Factors $factors,
        private SerializerInterface $serializer,
        private AuthenticatorAttestationResponseValidator $attestations,
        private AuthenticatorAssertionResponseValidator $assertions,
        private ClockInterface $clock,
        private string $relyingPartyName = '',
        private ?string $relyingPartyId = null,
        private int $timeout = 60000,
        private string $userVerification = 'preferred',
        private string $residentKey = 'discouraged',
        private int $labelMaxLength = 60,
    ) {
    }

    public function name(): string
    {
        return self::NAME;
    }

    public function countFor(string $userIdentifier): int
    {
        return \count($this->keys->findAllOf($userIdentifier));
    }

    public function manageAt(): string
    {
        return 'authentication_policy_security_key';
    }

    public function isRecovery(): bool
    {
        return false;
    }

    /** @return list<StoredKey> */
    public function keysOf(string $userIdentifier): array
    {
        return $this->keys->findAllOf($userIdentifier);
    }

    /**
     * Le défi que l'appareil devra signer pour se poser, et ses conditions.
     *
     * Les clés déjà posées sont écartées : l'appareil refuse alors de se poser deux fois, au
     * lieu de laisser croire à une seconde clé qui remplacerait la première.
     */
    public function beginEnrolment(string $userIdentifier, SessionInterface $session): string
    {
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('', $this->relyingPartyId),
            PublicKeyCredentialUserEntity::create(
                $userIdentifier,
                $this->keys->handleOf($userIdentifier),
                $userIdentifier,
            ),
            random_bytes(32),
            [
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_ES256),
                PublicKeyCredentialParameters::createPk(Algorithms::COSE_ALGORITHM_RS256),
            ],
            AuthenticatorSelectionCriteria::create(
                userVerification: $this->userVerification,
                residentKey: $this->residentKey,
            ),
            timeout: max(1, $this->timeout),
            excludeCredentials: $this->descriptorsOf($this->keys->findAllOf($userIdentifier)),
        );

        $serialized = $this->named($this->serialize($options));
        $session->set(self::ENROLMENT_KEY, $serialized);

        return $serialized;
    }

    /**
     * Range la clé si sa réponse tient, et rend son genre.
     *
     * Le nom vient de la personne : c'est le seul moyen de distinguer deux clés au moment d'en
     * retirer une.
     */
    public function finishEnrolment(
        string $userIdentifier,
        string $label,
        string $answer,
        SessionInterface $session,
        string $host,
    ): bool {
        $expected = $this->takeFromSession($session, self::ENROLMENT_KEY);

        if (null === $expected) {
            return false;
        }

        try {
            $credential = $this->serializer->deserialize($answer, PublicKeyCredential::class, 'json');
            $response = $credential->response;

            if (!$response instanceof AuthenticatorAttestationResponse) {
                return false;
            }

            $record = $this->attestations->check(
                $response,
                $this->serializer->deserialize($expected, PublicKeyCredentialCreationOptions::class, 'json'),
                $host,
            );
        } catch (\Throwable) {
            return false;
        }

        $encoded = base64_encode($record->publicKeyCredentialId);
        $now = $this->clock->now()->getTimestamp();

        $this->keys->save(new StoredKey(
            '' === $encoded ? '0' : $encoded,
            $userIdentifier,
            $this->keys->handleOf($userIdentifier),
            $this->trim($label, $userIdentifier),
            Kind::fromTransports(array_values($record->transports)),
            Record::encode($record),
            $now,
        ));

        return true;
    }

    /** Le défi de connexion : les clés admises, et les moyens par lesquels les interroger. */
    public function beginChallenge(string $userIdentifier, SessionInterface $session): string
    {
        $options = PublicKeyCredentialRequestOptions::create(
            random_bytes(32),
            rpId: $this->relyingPartyId,
            allowCredentials: $this->descriptorsOf($this->keys->findAllOf($userIdentifier)),
            userVerification: $this->userVerification,
            timeout: max(1, $this->timeout),
        );

        $serialized = $this->serialize($options);
        $session->set(self::CHALLENGE_KEY, $serialized);

        return $serialized;
    }

    public function verify(string $userIdentifier, string $answer, SessionInterface $session, string $host): bool
    {
        $expected = $this->takeFromSession($session, self::CHALLENGE_KEY);

        if (null === $expected) {
            return false;
        }

        try {
            $credential = $this->serializer->deserialize($answer, PublicKeyCredential::class, 'json');
            $response = $credential->response;
            $stored = $this->keys->findOneByCredentialId($credential->rawId);

            if (!$response instanceof AuthenticatorAssertionResponse
                || null === $stored
                || $stored->userIdentifier !== $userIdentifier) {
                return false;
            }

            $record = $this->assertions->check(
                Record::decode($stored->record),
                $response,
                $this->serializer->deserialize($expected, PublicKeyCredentialRequestOptions::class, 'json'),
                $host,
                $stored->userHandle,
            );
        } catch (\Throwable) {
            return false;
        }

        $this->keys->noteUsage($stored, Record::encode($record), $this->clock->now()->getTimestamp());

        return true;
    }

    /** @throws LastFactorRemoval si le compte n'a rien d'autre pour se connecter */
    public function removeFor(string $userIdentifier, string $credentialId): void
    {
        $key = $this->keys->findOneOf($userIdentifier, $credentialId);

        if (null === $key) {
            return;
        }

        $this->factors->requireRemovable($userIdentifier, $this->name());

        $this->keys->remove($key);
    }

    /**
     * Le nom du site, rétabli dans le JSON après la sérialisation.
     *
     * La bibliothèque déprécie ce nom et l'efface du bloc `rp` quand il est vide, alors que la
     * norme l'exige : sans lui, le navigateur refuse la demande, et son message ne dit pas
     * lequel des dix champs manque. Le rétablir ici plutôt que sur l'entité évite d'écrire dans
     * une propriété promise au retrait.
     */
    private function named(string $json): string
    {
        /** @var array<string, mixed> $options */
        $options = json_decode($json, true, 512, \JSON_THROW_ON_ERROR);

        /** @var array<string, mixed> $party */
        $party = $options['rp'] ?? [];
        $party['name'] = $this->relyingPartyName;
        $options['rp'] = $party;

        return json_encode($options, \JSON_THROW_ON_ERROR);
    }

    /**
     * Les moyens que chaque clé sait employer voyagent avec elle.
     *
     * Sans eux, le navigateur ignore qu'il doit interroger la prise USB, et une clé pourtant
     * branchée n'est **pas** proposée — il se rabat sur ce qu'il héberge lui-même.
     *
     * @param list<StoredKey> $keys
     *
     * @return list<PublicKeyCredentialDescriptor>
     */
    private function descriptorsOf(array $keys): array
    {
        return array_map(
            static fn (StoredKey $key): PublicKeyCredentialDescriptor => PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                $key->rawId(),
                $key->transports(),
            ),
            $keys,
        );
    }

    /**
     * Sans cette consigne, les réglages laissés libres partiraient à « null » et le navigateur
     * refuserait la demande : il attend qu'un réglage absent soit absent.
     */
    private function serialize(object $options): string
    {
        return $this->serializer->serialize($options, 'json', [AbstractObjectNormalizer::SKIP_NULL_VALUES => true]);
    }

    /** Le défi ne vaut qu'un aller-retour : le lire, c'est le retirer. */
    private function takeFromSession(SessionInterface $session, string $key): ?string
    {
        $expected = $session->get($key);
        $session->remove($key);

        return \is_string($expected) && '' !== $expected ? $expected : null;
    }

    private function trim(string $label, string $fallback): string
    {
        $clean = trim($label);

        return '' === $clean
            ? mb_substr($fallback, 0, $this->labelMaxLength)
            : mb_substr($clean, 0, $this->labelMaxLength);
    }
}
