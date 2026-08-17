<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey;

use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\Denormalizer\TrustPathDenormalizer;
use Webauthn\TrustPath\TrustPath;

/**
 * Ce qu'il faut garder d'une clé pour vérifier ses signatures plus tard, sous une forme qui
 * tient dans du texte.
 *
 * **L'enregistrement ne se sérialise pas d'un bloc.** L'identifiant, la partie publique et
 * l'identité opaque du compte sont des suites d'octets quelconques : les encoder en JSON tels
 * quels échoue sur un octet qui n'est pas de l'UTF-8, et le message ne dit pas lequel des
 * treize champs est en cause. Ils passent donc en base64, un par un.
 *
 * Les transports voyagent avec le reste, et c'est essentiel : sans eux, le navigateur ignore
 * qu'il doit interroger la prise USB, et une clé pourtant branchée n'est pas proposée.
 */
final readonly class Record
{
    /** @return non-empty-string */
    public static function encode(CredentialRecord $record): string
    {
        // Le tableau n'est jamais vide, donc l'encodage non plus : la garantie est écrite ici
        // pour que les rangements puissent l'exiger.
        return json_encode([
            'credentialId' => base64_encode($record->publicKeyCredentialId),
            'type' => $record->type,
            'transports' => $record->transports,
            'attestationType' => $record->attestationType,
            'trustPath' => (new TrustPathDenormalizer())->normalize($record->trustPath),
            'aaguid' => $record->aaguid->toRfc4122(),
            'publicKey' => base64_encode($record->credentialPublicKey),
            'userHandle' => base64_encode($record->userHandle),
            'counter' => $record->counter,
            'otherUI' => $record->otherUI,
            'backupEligible' => $record->backupEligible,
            'backupStatus' => $record->backupStatus,
            'uvInitialized' => $record->uvInitialized,
        ], \JSON_THROW_ON_ERROR);
    }

    public static function decode(string $stored): CredentialRecord
    {
        /** @var array<string, mixed> $held */
        $held = json_decode($stored, true, 512, \JSON_THROW_ON_ERROR);

        /** @var TrustPath $trustPath */
        $trustPath = (new TrustPathDenormalizer())->denormalize($held['trustPath'], TrustPath::class);

        return new CredentialRecord(
            (string) base64_decode((string) $held['credentialId'], true),
            (string) $held['type'],
            self::transportsOf($held),
            (string) $held['attestationType'],
            $trustPath,
            Uuid::fromString((string) $held['aaguid']),
            (string) base64_decode((string) $held['publicKey'], true),
            (string) base64_decode((string) $held['userHandle'], true),
            (int) $held['counter'],
            null === $held['otherUI'] ? null : (array) $held['otherUI'],
            null === $held['backupEligible'] ? null : (bool) $held['backupEligible'],
            null === $held['backupStatus'] ? null : (bool) $held['backupStatus'],
            null === $held['uvInitialized'] ? null : (bool) $held['uvInitialized'],
        );
    }

    /**
     * @param array<string, mixed> $held
     *
     * @return list<string>
     */
    public static function transportsOf(array $held): array
    {
        $transports = [];

        foreach ((array) ($held['transports'] ?? []) as $transport) {
            $transports[] = (string) $transport;
        }

        return $transports;
    }

    /** @return list<string> */
    public static function transportsIn(string $stored): array
    {
        /** @var array<string, mixed> $held */
        $held = json_decode($stored, true, 512, \JSON_THROW_ON_ERROR);

        return self::transportsOf($held);
    }

    private function __construct()
    {
    }
}
