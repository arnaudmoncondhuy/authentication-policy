<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\Parameter;
use ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection\RefuseLockWithoutExitPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;

/** Première garantie, première moitié : un verrou qui se ferme a une porte de sortie. */
final class RefuseLockWithoutExitPassTest extends TestCase
{
    public function testUnVerrouSansCheminNiMecanismeArreteLaCompilation(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: null, mechanism: false);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/enrollment_path/');

        (new RefuseLockWithoutExitPass())->process($container);
    }

    /**
     * Un verrou qui se ferme alors que rien n'est allumé enferme dehors : la page d'enrôlement
     * n'aurait alors rien à proposer de poser.
     */
    public function testUnVerrouSansMecanismeAllumeArreteLaCompilation(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: '/enrolement', mechanism: false);

        $this->expectException(LogicException::class);
        $this->expectExceptionMessageMatches('/mechanisms/');

        (new RefuseLockWithoutExitPass())->process($container);
    }

    /** Le verrou peut aussi se fermer par délégation : le plafond ne dit pas tout. */
    public function testUnVerrouDelegueSansSortieArreteAussiLaCompilation(): void
    {
        $container = $this->containerFor(
            ['two_factor' => ['ceiling' => false, 'delegated_to' => ['role']]],
            path: null,
            mechanism: false,
        );

        $this->expectException(LogicException::class);

        (new RefuseLockWithoutExitPass())->process($container);
    }

    public function testAvecLesDeuxLaCompilationPasse(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => true]], path: '/enrolement', mechanism: true);

        (new RefuseLockWithoutExitPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    public function testUnePolitiqueQuiNExigeRienNAPasBesoinDeSortie(): void
    {
        $container = $this->containerFor(['two_factor' => ['ceiling' => false]], path: null, mechanism: false);

        (new RefuseLockWithoutExitPass())->process($container);

        $this->expectNotToPerformAssertions();
    }

    /** @param array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules */
    private function containerFor(array $rules, ?string $path, bool $mechanism): ContainerBuilder
    {
        $container = new ContainerBuilder();
        $container->setParameter(Parameter::RULES, $rules);
        $container->setParameter(Parameter::ENROLLMENT_PATH, $path);
        $container->setParameter(Parameter::MECHANISMS, ['backup_codes' => ['enabled' => $mechanism]]);

        return $container;
    }
}
