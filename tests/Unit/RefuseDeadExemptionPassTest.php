<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseDeadExemptionPass;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\NotASurface;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\EnrollmentController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\ExemptedMethodController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\GuardedController;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/** Première garantie, seconde moitié : une dispense qui n'ouvre rien ment. */
final class RefuseDeadExemptionPassTest extends TestCase
{
    public function testUneDispenseHorsDUnePorteArreteLaCompilation(): void
    {
        $container = new ContainerBuilder();
        $container->setDefinition(NotASurface::class, new Definition(NotASurface::class));

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/'.preg_quote(NotASurface::class, '/').'/');

        (new RefuseDeadExemptionPass())->process($container);
    }

    public function testUneDispenseSurUnControleurPasse(): void
    {
        $container = new ContainerBuilder();
        $container->setDefinition(EnrollmentController::class, new Definition(EnrollmentController::class))
            ->addTag('controller.service_arguments');

        (new RefuseDeadExemptionPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUneDispenseSurUneMethodeDeControleurPasse(): void
    {
        $container = new ContainerBuilder();
        $container->setDefinition(ExemptedMethodController::class, new Definition(ExemptedMethodController::class))
            ->addTag('controller.service_arguments');

        (new RefuseDeadExemptionPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUnePorteSansDispenseNeConcernePasLaPasse(): void
    {
        $container = new ContainerBuilder();
        $container->setDefinition(GuardedController::class, new Definition(GuardedController::class))
            ->addTag('controller.service_arguments');

        (new RefuseDeadExemptionPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    /** Une application qui ouvre une porte d'un autre genre déclare sa marque. */
    public function testUneMarqueDeclareeParLApplicationCompteCommePorte(): void
    {
        $container = new ContainerBuilder();
        $container->setParameter(Parameter::EXTRA_SURFACE_TAGS, ['app.mcp_tool']);
        $container->setDefinition(NotASurface::class, new Definition(NotASurface::class))
            ->addTag('app.mcp_tool');

        (new RefuseDeadExemptionPass())->process($container);

        $this->expectNotToPerformAssertions();
    }
}
