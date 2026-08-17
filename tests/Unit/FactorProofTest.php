<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Unit;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\FactorProof;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ProvenMoment;
use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\FrozenClock;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFactor;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Fixture\StubFirewall;
use ArnaudMoncondhuy\Authorization\Proof;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\User\InMemoryUser;

/**
 * Ce que ce paquet répond au paquet qui décide des droits.
 *
 * Deux réponses seulement, et la seconde est la plus délicate : ce n'est pas parce qu'on a
 * prouvé son identité il y a une heure qu'on vient de la prouver.
 */
final class FactorProofTest extends TestCase
{
    private FrozenClock $clock;
    private RequestStack $requests;

    protected function setUp(): void
    {
        $this->clock = new FrozenClock();
        $this->requests = new RequestStack();

        $request = new Request();
        $request->setSession(new Session(new MockArraySessionStorage()));

        $this->requests->push($request);
    }

    /** Rien à prouver : le niveau nul se satisfait avant même de regarder qui est là. */
    public function testTheNoneLevelIsAlwaysMet(): void
    {
        self::assertTrue($this->proof(posed: 0)->meets(Proof::None));
    }

    /**
     * Hors du périmètre, le paquet ne se prononce pas et laisse passer. Une machine ne posera
     * jamais de second facteur : lui opposer un détour la mettrait dehors sans porte.
     */
    public function testOutsideThePerimeterItDoesNotDecide(): void
    {
        $proof = $this->proof(posed: 0, firewall: 'machines');

        self::assertTrue($proof->meets(Proof::Strong));
        self::assertTrue($proof->meets(Proof::Recent));
    }

    /** Un compte sans moyen n'a rien présenté et ne peut rien présenter. */
    public function testAnAccountWithoutAnyFactorProvesNothing(): void
    {
        self::assertFalse($this->proof(posed: 0)->meets(Proof::Strong));
    }

    /**
     * Un moyen posé vaut un moyen présenté : le paquet le réclame à la connexion dès qu'il
     * existe, et la session en cours l'a donc franchi.
     */
    public function testAnEquippedAccountMeetsTheStrongLevel(): void
    {
        self::assertTrue($this->proof(posed: 1)->meets(Proof::Strong));
    }

    /** Sans rien de présenté dans cette session, rien n'est récent. */
    public function testWithoutAMomentNothingIsRecent(): void
    {
        self::assertFalse($this->proof(posed: 1)->meets(Proof::Recent));
    }

    public function testAProofJustGivenIsRecent(): void
    {
        $moment = $this->moment();
        $moment->record();

        self::assertTrue($this->proof(posed: 1, moment: $moment)->meets(Proof::Recent));
    }

    /** Le niveau supérieur se perd en premier : la fraîcheur passe, le moyen reste. */
    public function testAnOldProofStopsBeingRecentWithoutStoppingToBeStrong(): void
    {
        $moment = $this->moment();
        $moment->record();

        $this->clock->advance(901);

        $proof = $this->proof(posed: 1, moment: $moment);

        self::assertFalse($proof->meets(Proof::Recent));
        self::assertTrue($proof->meets(Proof::Strong));
    }

    /** La limite est incluse : à la seconde près, la preuve vaut encore. */
    public function testTheEdgeOfTheWindowStillCounts(): void
    {
        $moment = $this->moment();
        $moment->record();

        $this->clock->advance(900);

        self::assertTrue($this->proof(posed: 1, moment: $moment)->meets(Proof::Recent));
    }

    /** Personne de connecté : rien n'est prouvé, et le doute se referme. */
    public function testWithoutAnyoneConnectedNothingIsProven(): void
    {
        self::assertFalse($this->proof(posed: 1, connected: false)->meets(Proof::Strong));
    }

    private function moment(): ProvenMoment
    {
        return new ProvenMoment($this->requests, $this->clock);
    }

    private function proof(
        int $posed,
        string $firewall = 'main',
        bool $connected = true,
        ?ProvenMoment $moment = null,
    ): FactorProof {
        $tokens = new TokenStorage();

        if ($connected) {
            $tokens->setToken(new UsernamePasswordToken(new InMemoryUser('arnaud', null), 'main'));
        }

        return new FactorProof(
            new Factors([new StubFactor($posed, 'essai')], true),
            new Visitor($tokens, new Perimeter(['main']), new StubFirewall($firewall)),
            $moment ?? $this->moment(),
            900,
        );
    }
}
