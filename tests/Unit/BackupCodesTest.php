<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodes;
use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes\BackupCodeStore;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryBackupCodeStore;
use PHPUnit\Framework\TestCase;

/**
 * Ce qu'un code de secours doit tenir : servir une fois, ne jamais se relire en clair, et ne
 * pas disparaître en emportant le dernier moyen d'entrer.
 */
final class BackupCodesTest extends TestCase
{
    public function testUneSeriePoseeEstRendueUneSeuleFois(): void
    {
        $store = new InMemoryBackupCodeStore();
        $codes = self::backupCodes($store)->generateFor('claude');

        self::assertCount(BackupCodes::HOW_MANY, $codes);
        self::assertCount(BackupCodes::HOW_MANY, array_unique($codes));

        // Ce qui est rangé ne ressemble à aucun des codes rendus.
        foreach ($store->hashesFor('claude') as $hash) {
            self::assertNotContains($hash, $codes);
        }
    }

    public function testUnCodeJusteOuvreUneFoisEtUneSeule(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $codes = $backupCodes->generateFor('claude');

        self::assertTrue($backupCodes->consume('claude', $codes[0]));
        self::assertFalse($backupCodes->consume('claude', $codes[0]));
        self::assertSame(BackupCodes::HOW_MANY - 1, $backupCodes->countFor('claude'));
    }

    public function testUnCodeInconnuNOuvreRien(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $backupCodes->generateFor('claude');

        self::assertFalse($backupCodes->consume('claude', 'ffff-ffff-ffff-ffff'));
        self::assertSame(BackupCodes::HOW_MANY, $backupCodes->countFor('claude'));
    }

    /**
     * Le code est recopié à la main depuis un papier : refuser une majuscule ou un tiret oublié
     * n'écarterait personne d'autre que la personne légitime.
     */
    public function testLaSaisieToleranteNAffaiblitPasLaVerification(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $codes = $backupCodes->generateFor('claude');

        self::assertTrue($backupCodes->consume('claude', strtoupper(str_replace('-', ' ', $codes[0]))));
    }

    public function testLesCodesDUnCompteNOuvrentPasCeluiDUnAutre(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $codes = $backupCodes->generateFor('claude');
        $backupCodes->generateFor('arnaud');

        self::assertFalse($backupCodes->consume('arnaud', $codes[0]));
    }

    public function testPoserUneNouvelleSeriePerimeLAncienne(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $anciens = $backupCodes->generateFor('claude');
        $backupCodes->generateFor('claude');

        self::assertFalse($backupCodes->consume('claude', $anciens[0]));
        self::assertSame(BackupCodes::HOW_MANY, $backupCodes->countFor('claude'));
    }

    public function testRetirerLaSerieQuandElleEstLeDernierMoyenEstRefuse(): void
    {
        $store = new InMemoryBackupCodeStore();
        $backupCodes = self::backupCodes($store);
        $backupCodes->generateFor('claude');

        $this->expectException(LastFactorRemoval::class);

        $backupCodes->discardFor('claude');
    }

    private static function backupCodes(BackupCodeStore $store): BackupCodes
    {
        $factors = new Factors([], true);
        $backupCodes = new BackupCodes($store, $factors);

        // Le registre compte le mécanisme qu'il protège : autrement, retirer la série paraîtrait
        // sans conséquence.
        return new BackupCodes($store, new Factors([$backupCodes], true));
    }
}
