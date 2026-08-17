<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\EnrollmentLockListener;
use ArnaudMoncondhuy\AuthenticationPolicy\Decider;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\Policy;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\Rule;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\InMemoryRolePolicies;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFactor;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFirewall;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\EnrollmentController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\ExemptedMethodController;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\Web\GuardedController;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\HttpKernel\HttpKernelInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Le verrou, et surtout son sens : fermé d'abord, ouvert sur déclaration.
 *
 * Le premier test est celui qui compte. Une page qui ne déclare rien — le cas de toutes celles
 * qu'on écrira demain — doit être fermée sans que personne ait eu à y penser.
 */
final class EnrollmentLockListenerTest extends TestCase
{
    public function testUnePageQuiNeDeclareRienEstFermee(): void
    {
        $event = $this->eventFor(new GuardedController());

        $this->lockFor(posed: 0)($event);

        self::assertInstanceOf(RedirectResponse::class, ($event->getController())());
    }

    public function testUnePageDispenseeResteJoignable(): void
    {
        $event = $this->eventFor(new EnrollmentController());

        $this->lockFor(posed: 0)($event);

        self::assertSame('la page qui enrôle', ($event->getController())()->getContent());
    }

    public function testUneDispenseSurUneMethodeNOuvrePasLesAutres(): void
    {
        $controller = new ExemptedMethodController();

        $exempted = $this->eventFor([$controller, 'backupCodes']);
        $this->lockFor(posed: 0)($exempted);
        self::assertSame('les codes de secours', ($exempted->getController())()->getContent());

        $guarded = $this->eventFor([$controller, 'settings']);
        $this->lockFor(posed: 0)($guarded);
        self::assertInstanceOf(RedirectResponse::class, ($guarded->getController())());
    }

    public function testQuiAPoseUnMoyenTraverseLeVerrou(): void
    {
        $event = $this->eventFor(new GuardedController());

        $this->lockFor(posed: 1)($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    public function testLeCheminDEnrolementResteJoignableMemeSansDispense(): void
    {
        $event = $this->eventFor(new GuardedController(), path: '/enrolement/etape-2');

        $this->lockFor(posed: 0)($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    public function testSansCompteConnecteLeVerrouNeLitRien(): void
    {
        $event = $this->eventFor(new GuardedController());

        $this->lockFor(posed: 0, token: false)($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    /** Un compte dont la politique n'exige rien — un pare-feu de machines, par exemple. */
    public function testUnRoleSansExigenceTraverse(): void
    {
        $event = $this->eventFor(new GuardedController());

        $this->lockFor(posed: 0, roles: ['ROLE_SERVICE'])($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    public function testUneSousRequeteNEstPasVerrouillee(): void
    {
        $event = $this->eventFor(new GuardedController(), type: HttpKernelInterface::SUB_REQUEST);

        $this->lockFor(posed: 0)($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    /** Un compte de machine, sur le pare-feu que le périmètre ne nomme pas. */
    public function testUnPareFeuHorsDuPerimetreNEstPasVerrouille(): void
    {
        $event = $this->eventFor(new GuardedController());

        $this->lockFor(posed: 0, firewall: 'machines')($event);

        self::assertSame('la page ordinaire', ($event->getController())()->getContent());
    }

    /**
     * @param int          $posed combien de moyens le compte a posés
     * @param list<string> $roles
     */
    private function lockFor(
        int $posed,
        array $roles = ['ROLE_ADMIN'],
        bool $token = true,
        ?string $firewall = 'main',
    ): EnrollmentLockListener {
        $tokens = new TokenStorage();

        if ($token) {
            $tokens->setToken(new UsernamePasswordToken(new InMemoryUser('arnaud', null, $roles), 'main', $roles));
        }

        $resolver = new PolicyResolver(
            new Policy([new Rule(Setting::TwoFactor, false, [Decider::Role])]),
            new InMemoryRolePolicies(['ROLE_ADMIN' => ['two_factor' => true]]),
        );

        return new EnrollmentLockListener(
            $resolver,
            $tokens,
            new Factors([new StubFactor($posed)], true),
            new Perimeter(['main']),
            new StubFirewall($firewall),
            '/enrolement',
        );
    }

    private function eventFor(
        callable $controller,
        string $path = '/une-page',
        int $type = HttpKernelInterface::MAIN_REQUEST,
    ): ControllerEvent {
        return new ControllerEvent(
            $this->createStub(HttpKernelInterface::class),
            $controller,
            Request::create($path),
            $type,
        );
    }
}
