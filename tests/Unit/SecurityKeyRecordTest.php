<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\Kind;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\Record;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * La conversion d'un enregistrement de clé en texte, et retour.
 *
 * C'est le seul endroit du mécanisme où une faute ne se voit pas en lisant : trois champs sont
 * des suites d'octets quelconques, et les encoder d'un bloc échoue sur le premier qui n'est pas
 * de l'UTF-8 — sur une base déjà remplie, et pour un compte seulement.
 */
final class SecurityKeyRecordTest extends TestCase
{
    public function testUnEnregistrementFaitDOctetsQuelconquesSurvitAuTexte(): void
    {
        // Soixante-quatre octets tirés au sort : la probabilité qu'ils forment de l'UTF-8
        // valide est négligeable, ce qui fait de ce cas le pire réaliste.
        $original = new CredentialRecord(
            random_bytes(32),
            'public-key',
            ['usb', 'nfc'],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            random_bytes(64),
            random_bytes(32),
            17,
            null,
            true,
            false,
            true,
        );

        $revenu = Record::decode(Record::encode($original));

        self::assertSame($original->publicKeyCredentialId, $revenu->publicKeyCredentialId);
        self::assertSame($original->credentialPublicKey, $revenu->credentialPublicKey);
        self::assertSame($original->userHandle, $revenu->userHandle);
        self::assertSame($original->counter, $revenu->counter);
        self::assertSame($original->backupEligible, $revenu->backupEligible);
        self::assertSame($original->uvInitialized, $revenu->uvInitialized);
    }

    /**
     * Sans les transports, le navigateur ignore qu'il doit interroger la prise USB : une clé
     * pourtant branchée n'est pas proposée, et rien ne le dit.
     */
    public function testLesTransportsVoyagentAvecLEnregistrement(): void
    {
        $original = new CredentialRecord(
            random_bytes(16),
            'public-key',
            ['usb'],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            random_bytes(32),
            random_bytes(32),
            0,
        );

        $encoded = Record::encode($original);

        self::assertSame(['usb'], Record::transportsIn($encoded));
        self::assertSame(['usb'], Record::decode($encoded)->transports);
    }

    public function testLeGenreSeDeduitDeCeQueLAppareilDeclare(): void
    {
        self::assertSame(Kind::Device, Kind::fromTransports(['internal']));
        self::assertSame(Kind::Phone, Kind::fromTransports(['hybrid']));
        self::assertSame(Kind::Portable, Kind::fromTransports(['usb', 'nfc']));

        // Un appareil qui ne déclare rien reste indéterminé plutôt que mal rangé.
        self::assertSame(Kind::Unknown, Kind::fromTransports([]));
    }
}
