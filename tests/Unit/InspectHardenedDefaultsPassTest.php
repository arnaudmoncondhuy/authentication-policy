<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\InspectHardenedDefaultsPass;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/** Le relevé des durcissements qui n'appartiennent pas au paquet, et que rien d'autre ne signale. */
final class InspectHardenedDefaultsPassTest extends TestCase
{
    public function testUneSessionPurgeeAvantLInactiviteAnnonceeEstSignalee(): void
    {
        $findings = $this->findingsFor(
            ['idle_timeout' => ['ceiling' => 28800]],
            ['gc_maxlifetime' => 1440],
        );

        self::assertCount(1, $findings);
        self::assertStringContainsString('28800', $findings[0]);
        self::assertStringContainsString('1440', $findings[0]);
    }

    public function testUnStockageAssezGenereuxNeDitRien(): void
    {
        self::assertSame([], $this->findingsFor(
            ['idle_timeout' => ['ceiling' => 1440]],
            ['gc_maxlifetime' => 28800],
        ));
    }

    public function testSansInactiviteAnnonceeIlNYAUneRienAComparer(): void
    {
        self::assertSame([], $this->findingsFor([], ['gc_maxlifetime' => 1440]));
    }

    public function testUnCookieRelacheEstSignale(): void
    {
        $findings = $this->findingsFor([], ['cookie_secure' => false, 'cookie_samesite' => null]);

        self::assertCount(2, $findings);
    }

    /**
     * @param array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules
     * @param array<string, mixed>                                                       $session
     *
     * @return list<string>
     */
    private function findingsFor(array $rules, array $session): array
    {
        $container = new ContainerBuilder();
        $container->setParameter(Parameter::RULES, $rules);
        $container->setParameter('session.storage.options', $session);

        (new InspectHardenedDefaultsPass())->process($container);

        /** @var list<string> $findings */
        $findings = $container->getParameter(Parameter::FINDINGS);

        return $findings;
    }
}
