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
     * Hors du périmètre, le paquet ne sait rien — et ce qu'on ne sait pas, on le refuse.
     *
     * Laisser passer ferait des portes qu'il ne garde pas le chemin le plus court vers un droit
     * qui exigeait une preuve : une file, une console, un pare-feu machine accorderaient ce que
     * l'écran refuse. Il est vrai qu'une machine ne posera jamais de second facteur et se
     * retrouve donc dehors sans porte — mais c'est le signe qu'un tel droit ne devait pas lui
     * être accordé, et il vaut mieux le voir que se le faire accorder en silence.
     */
    public function testOutsideThePerimeterItRefuses(): void
    {
        $proof = $this->proof(posed: 0, firewall: 'machines');

        self::assertFalse($proof->meets(Proof::Strong));
        self::assertFalse($proof->meets(Proof::Recent));
    }

    /** Ce qui n'exige rien passe partout, y compris hors du périmètre. */
    public function testOutsideThePerimeterNothingRequiredStillPasses(): void
    {
        self::assertTrue($this->proof(posed: 0, firewall: 'machines')->meets(Proof::None));
    }

    /** Un compte sans moyen n'a rien présenté et ne peut rien présenter. */
    public function testAnAccountWithoutAnyFactorProvesNothing(): void
    {
        self::assertFalse($this->proof(posed: 0)->meets(Proof::Strong));
    }

    /**
     * Un moyen posé ne vaut pas un moyen présenté.
     *
     * Il dit ce que le compte pourrait montrer, pas ce que la personne devant l'écran a montré.
     * Croire l'un pour l'autre suppose que le moyen soit réclamé à chaque entrée — ce qu'une
     * politique qui ne l'exige pas, un « se souvenir de moi » ou un appareil de confiance
     * démentent. Le niveau se refermerait alors sur le seul cas qu'il prétend arrêter.
     */
    public function testAnEquippedAccountThatPresentedNothingIsNotStrong(): void
    {
        self::assertFalse($this->proof(posed: 1)->meets(Proof::Strong));
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
