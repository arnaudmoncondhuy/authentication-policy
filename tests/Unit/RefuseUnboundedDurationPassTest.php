<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseUnboundedDurationPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/** Troisième garantie : une durée déléguée part d'un plafond, jamais de l'infini. */
final class RefuseUnboundedDurationPassTest extends TestCase
{
    public function testDeleguerUneDureeSansPlafondArreteLaCompilation(): void
    {
        $container = $this->containerFor(['idle_timeout' => ['delegated_to' => ['role']]]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/idle_timeout/');

        (new RefuseUnboundedDurationPass())->process($container);
    }

    public function testAvecUnPlafondLaDelegationPasse(): void
    {
        $container = $this->containerFor(['idle_timeout' => ['ceiling' => 28800, 'delegated_to' => ['role']]]);

        (new RefuseUnboundedDurationPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUneDureeNonDelegueeNAPasBesoinDePlafond(): void
    {
        $container = $this->containerFor(['idle_timeout' => ['delegated_to' => []]]);

        (new RefuseUnboundedDurationPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUneExigenceDelegueeSansPlafondNEstPasVisee(): void
    {
        $container = $this->containerFor(['two_factor' => ['delegated_to' => ['role', 'user']]]);

        (new RefuseUnboundedDurationPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    /** @param array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules */
    private function containerFor(array $rules): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter(Parameter::RULES, $rules);

        return $container;
    }
}
