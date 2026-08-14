<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\InvalidSettingValue;
use ArnaudMoncondhuy\AuthenticationPolicy\Kind;
use PHPUnit\Framework\TestCase;

/**
 * L'algèbre sur laquelle repose la garantie : un niveau ne peut que resserrer.
 *
 * Si ces assertions tombent, la promesse du paquet tombe avec elles — pas un contrôle, la
 * promesse elle-même.
 */
final class KindTest extends TestCase
{
    public function testUneExigenceSeDurcitVersLeVrai(): void
    {
        self::assertTrue(Kind::Requirement->restrict(false, true));
        self::assertTrue(Kind::Requirement->restrict(true, false));
        self::assertFalse(Kind::Requirement->restrict(false, false));
    }

    public function testUnePermissionSeDurcitVersLeFaux(): void
    {
        self::assertFalse(Kind::Permission->restrict(true, false));
        self::assertFalse(Kind::Permission->restrict(false, true));
        self::assertTrue(Kind::Permission->restrict(true, true));
    }

    public function testUneDureeSeDurcitVersLeCourt(): void
    {
        self::assertSame(60, Kind::Duration->restrict(3600, 60));
        self::assertSame(60, Kind::Duration->restrict(60, 3600));
    }

    /**
     * L'ordre dans lequel plusieurs rôles s'expriment ne doit rien changer : quelqu'un qui en
     * porte trois ne doit pas dépendre du rangement de sa table.
     */
    public function testLeRepliementNeDependPasDeLOrdre(): void
    {
        foreach ([Kind::Requirement, Kind::Permission] as $kind) {
            foreach ([[true, false], [false, true], [true, true], [false, false]] as [$a, $b]) {
                self::assertSame($kind->restrict($a, $b), $kind->restrict($b, $a));
            }
        }

        self::assertSame(Kind::Duration->restrict(10, 20), Kind::Duration->restrict(20, 10));
    }

    public function testLaValeurLaPlusPermissiveEstLePointDeDepart(): void
    {
        self::assertFalse(Kind::Requirement->loosest());
        self::assertTrue(Kind::Permission->loosest());
        self::assertSame(\PHP_INT_MAX, Kind::Duration->loosest());
    }

    public function testUneDureeNAtteintJamaisLePlusStrict(): void
    {
        self::assertTrue(Kind::Requirement->isStrictest(true));
        self::assertFalse(Kind::Requirement->isStrictest(false));
        self::assertTrue(Kind::Permission->isStrictest(false));
        self::assertFalse(Kind::Duration->isStrictest(1));
    }

    public function testUneDureeRefuseCeQuiNEstPasUnNombreDeSecondes(): void
    {
        $this->expectException(InvalidSettingValue::class);

        Kind::Duration->refuseForeignValue(true);
    }

    public function testUneDureeNulleFermeraitLaPorteATous(): void
    {
        $this->expectException(InvalidSettingValue::class);

        Kind::Duration->refuseForeignValue(0);
    }

    public function testUneExigenceRefuseUnNombre(): void
    {
        $this->expectException(InvalidSettingValue::class);

        Kind::Requirement->refuseForeignValue(1);
    }
}
