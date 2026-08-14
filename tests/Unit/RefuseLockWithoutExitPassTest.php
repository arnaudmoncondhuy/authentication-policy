<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseLockWithoutExitPass;
use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryEnrollment;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/** Première garantie, première moitié : un verrou qui se ferme a une porte de sortie. */
final class RefuseLockWithoutExitPassTest extends TestCase
{
    public function testUnVerrouSansCheminNiServiceArreteLaCompilation(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: null, enrollment: false);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/enrollment_path/');

        (new RefuseLockWithoutExitPass())->process($container);
    }

    public function testUnVerrouSansServiceDEnrolementArreteLaCompilation(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: '/enrolement', enrollment: false);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/'.preg_quote(Enrollment::class, '/').'/');

        (new RefuseLockWithoutExitPass())->process($container);
    }

    /** Le verrou peut aussi se fermer par délégation : le plafond ne dit pas tout. */
    public function testUnVerrouDelegueSansSortieArreteAussiLaCompilation(): void
    {
        $container = $this->containerFor(
            ['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]],
            path: null,
            enrollment: false,
        );

        $this->expectException(LogicException::class);

        (new RefuseLockWithoutExitPass())->process($container);
    }

    public function testAvecLesDeuxLaCompilationPasse(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: '/enrolement', enrollment: true);

        (new RefuseLockWithoutExitPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUnePolitiqueQuiNExigeRienNAPasBesoinDeSortie(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => false]], path: null, enrollment: false);

        (new RefuseLockWithoutExitPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    /** @param array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules */
    private function containerFor(array $rules, ?string $path, bool $enrollment): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter(Parameter::RULES, $rules);
        $container->setParameter(Parameter::ENROLLMENT_PATH, $path);

        if ($enrollment) {
            $container->setDefinition(Enrollment::class, new Definition(InMemoryEnrollment::class));
        }

        return $container;
    }
}
