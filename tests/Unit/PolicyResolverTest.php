<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\InvalidSettingValue;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\ResolverBuilder;
use ArnaudMoncondhuy\AuthenticationPolicy\UnknownSetting;
use PHPUnit\Framework\TestCase;

/** La résolution : trois niveaux, un seul sens. */
final class PolicyResolverTest extends TestCase
{
    public function testSansRienDeDelegueLaConfigurationDecideSeule(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::TwoFactor, true),
        )->decideFor('arnaud');

        $decision = $decisions->of(Setting::TwoFactor);

        self::assertTrue($decision->requires());
        self::assertSame(Decider::Hardcoded, $decision->decidedBy);
        self::assertTrue($decision->locked);
    }

    public function testUnReglageAbsentDeLaConfigurationResteAuPlusPermissif(): void
    {
        $decisions = $this->resolver()->decideFor('arnaud');

        self::assertFalse($decisions->requires(Setting::TwoFactor));
        self::assertTrue($decisions->allows(Setting::RememberMe));
        self::assertSame(\PHP_INT_MAX, $decisions->seconds(Setting::IdleTimeout));
    }

    public function testUnRoleResserre(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::TwoFactor, false, [Decider::Role]),
        )
            ->withRoles(['ROLE_ADMIN' => ['two_factor' => true]])
            ->decideFor('arnaud', 'ROLE_ADMIN');

        $decision = $decisions->of(Setting::TwoFactor);

        self::assertTrue($decision->requires());
        self::assertSame(Decider::Role, $decision->decidedBy);
    }

    /**
     * Le cœur de la garantie. Un rôle qui pose trente jours sous un plafond de huit heures
     * n'obtient pas trente jours : il n'existe pas de chemin de code qui remonte.
     */
    public function testUnRoleNePeutPasDesserrerLePlafond(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::IdleTimeout, 28800, [Decider::Role]),
            new Rule(Setting::TwoFactor, true, [Decider::Role]),
            new Rule(Setting::RememberMe, false, [Decider::Role]),
        )
            ->withRoles(['ROLE_ADMIN' => [
                'idle_timeout' => 2592000,
                'two_factor' => false,
                'remember_me' => true,
            ]])
            ->decideFor('arnaud', 'ROLE_ADMIN');

        self::assertSame(28800, $decisions->seconds(Setting::IdleTimeout));
        self::assertTrue($decisions->requires(Setting::TwoFactor));
        self::assertFalse($decisions->allows(Setting::RememberMe));
    }

    public function testUnePersonneNePeutPasDesserrerSonRole(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::IdleTimeout, 86400, [Decider::Role, Decider::User]),
        )
            ->withRoles(['ROLE_ADMIN' => ['idle_timeout' => 28800]])
            ->withPreferences(['arnaud' => ['idle_timeout' => 2592000]])
            ->decideFor('arnaud', 'ROLE_ADMIN');

        self::assertSame(28800, $decisions->seconds(Setting::IdleTimeout));
        self::assertSame(Decider::Role, $decisions->of(Setting::IdleTimeout)->decidedBy);
    }

    public function testUnePersonnePeutResserrerEncore(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::IdleTimeout, 86400, [Decider::Role, Decider::User]),
        )
            ->withRoles(['ROLE_ADMIN' => ['idle_timeout' => 28800]])
            ->withPreferences(['arnaud' => ['idle_timeout' => 900]])
            ->decideFor('arnaud', 'ROLE_ADMIN');

        self::assertSame(900, $decisions->seconds(Setting::IdleTimeout));
        self::assertSame(Decider::User, $decisions->of(Setting::IdleTimeout)->decidedBy);
        self::assertFalse($decisions->of(Setting::IdleTimeout)->locked);
    }

    public function testLePlusStrictDeDeuxRolesGagneQuelQueSoitLOrdre(): void
    {
        $resolver = $this->resolver(new Rule(Setting::IdleTimeout, 86400, [Decider::Role]))
            ->withRoles([
                'ROLE_USER' => ['idle_timeout' => 28800],
                'ROLE_ADMIN' => ['idle_timeout' => 3600],
            ]);

        self::assertSame(3600, $resolver->decideFor('a', 'ROLE_USER', 'ROLE_ADMIN')->seconds(Setting::IdleTimeout));
        self::assertSame(3600, $resolver->decideFor('a', 'ROLE_ADMIN', 'ROLE_USER')->seconds(Setting::IdleTimeout));
    }

    public function testUneValeurStockeePourUnNiveauNonDelegueEstEcarteeEtRendueVisible(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::TwoFactor, false, [Decider::Role]),
        )
            ->withPreferences(['arnaud' => ['two_factor' => true]])
            ->decideFor('arnaud');

        self::assertFalse($decisions->requires(Setting::TwoFactor));
        self::assertCount(1, $decisions->ignored());
        self::assertSame(Setting::TwoFactor, $decisions->ignored()[0]->setting);
        self::assertSame(Decider::User, $decisions->ignored()[0]->from);
    }

    public function testUnVerrouSeLeveDesQueLaPersonnePeutEncoreResserrer(): void
    {
        $decisions = $this->resolver(
            new Rule(Setting::TwoFactor, false, [Decider::User]),
        )->decideFor('arnaud');

        self::assertFalse($decisions->of(Setting::TwoFactor)->locked);
    }

    public function testUnReglageInconnuEnBaseArreteLaResolution(): void
    {
        $this->expectException(UnknownSetting::class);

        $this->resolver()
            ->withPreferences(['arnaud' => ['deux_facteurs' => true]])
            ->decideFor('arnaud');
    }

    public function testUneValeurDuMauvaisTypeArreteLaResolution(): void
    {
        $this->expectException(InvalidSettingValue::class);

        $this->resolver(new Rule(Setting::IdleTimeout, 3600, [Decider::User]))
            ->withPreferences(['arnaud' => ['idle_timeout' => true]])
            ->decideFor('arnaud');
    }

    public function testToutReglageRecoitUneDecision(): void
    {
        $decisions = $this->resolver()->decideFor('arnaud');

        self::assertCount(\count(Setting::all()), $decisions->all());
    }

    private function resolver(Rule ...$rules): ResolverBuilder
    {
        return new ResolverBuilder(new Policy($rules));
    }
}
