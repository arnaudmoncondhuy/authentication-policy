<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDelegationWithoutStorePass;
use ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryRolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/** Deuxième garantie : ce qui est délégué a un endroit où se ranger. */
final class RefuseDelegationWithoutStorePassTest extends TestCase
{
    public function testDeleguerAuRoleSansStockageArreteLaCompilation(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/two_factor/');

        (new RefuseDelegationWithoutStorePass())->process($container);
    }

    public function testDeleguerALaPersonneSansStockageArreteLaCompilation(): void
    {
        $container = $this->containerFor(['remember_me' => ['ceiling' => true, 'delegated_to' => ['user']]]);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/'.preg_quote(UserPreferences::class, '/').'/');

        (new RefuseDelegationWithoutStorePass())->process($container);
    }

    public function testAvecLeStockageBrancheLaCompilationPasse(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]]);
        $container->setDefinition(RolePolicies::class, new Definition(InMemoryRolePolicies::class));

        (new RefuseDelegationWithoutStorePass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testSansDelegationRienNEstReclame(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true, 'delegated_to' => []]]);

        (new RefuseDelegationWithoutStorePass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testSansPolitiqueLaPasseSeTait(): void
    {
        (new RefuseDelegationWithoutStorePass())->process(new ContainerBuilder());

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
