<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Tests\Integration;

use ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\SecurityKey\SecurityKey;
use ArnaudMoncondhuy\AuthenticationPolicy\Tests\Kernel\PolicyTestKernel;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\HttpKernelInterface;

/**
 * Le montage des clés dans une application qui démarre, et surtout la forme du défi.
 *
 * La cérémonie elle-même ne se prouve qu'avec un navigateur ; ce qui se prouve ici est tout ce
 * qui la précède, et dont un défaut ne se manifeste qu'au moment où l'appareil refuse.
 */
final class SecurityKeyScreenTest extends TestCase
{
    private ?PolicyTestKernel $kernel = null;

    protected function tearDown(): void
    {
        $this->kernel?->shutdown();
        $this->kernel = null;
    }

    public function testLEcranSAfficheEtLeMecanismeEstCompte(): void
    {
        $kernel = $this->boot();

        $response = $this->visit($kernel, '/securite/cles');

        self::assertSame(Response::HTTP_OK, $response->getStatusCode());
        self::assertTrue($kernel->getContainer()->has(SecurityKey::class));
        self::assertStringContainsString('Poser une clé', (string) $response->getContent());
    }

    /**
     * Le navigateur refuse une demande dont un réglage vaut « null » : il attend qu'un réglage
     * absent soit absent. Le message qu'il rend ne dit pas lequel des dix est en cause.
     */
    public function testLeDefiNePorteAucunReglageNul(): void
    {
        $options = $this->optionsOf($this->boot());

        self::assertStringNotContainsString(':null', $options);
        self::assertStringNotContainsString(': null', $options);
    }

    /** Sans nom de site, le navigateur refuse la demande — et la configuration l'exige. */
    public function testLeDefiPorteLeNomDuSite(): void
    {
        $options = json_decode($this->optionsOf($this->boot()), true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($options);
        self::assertSame('Le test', $options['rp']['name'] ?? null);
        self::assertNotSame('', $options['challenge'] ?? '');
    }

    /**
     * L'identité opaque du compte est fabriquée par le paquet : il ne connaît pas la clé
     * primaire des comptes, et ne peut donc pas l'emprunter.
     */
    public function testLIdentiteOpaqueDuCompteEstFabriqueeParLePaquet(): void
    {
        $options = json_decode($this->optionsOf($this->boot()), true, 512, \JSON_THROW_ON_ERROR);

        self::assertIsArray($options);
        self::assertSame('arnaud', $options['user']['name'] ?? null);
        self::assertNotSame('', $options['user']['id'] ?? '');
    }

    private function optionsOf(PolicyTestKernel $kernel): string
    {
        $page = (string) $this->visit($kernel, '/securite/cles')->getContent();

        preg_match('/data-authentication-policy-security-key-options-value="([^"]*)"/', $page, $matches);

        self::assertArrayHasKey(1, $matches, 'Le défi doit voyager jusqu’au comportement, sous le nom qu’il attend.');

        return html_entity_decode($matches[1], \ENT_QUOTES, 'UTF-8');
    }

    private function boot(): PolicyTestKernel
    {
        $this->kernel?->shutdown();

        $this->kernel = new PolicyTestKernel([
            'firewalls' => ['main'],
            'storage' => ['connection' => PolicyTestKernel::CONNECTION],
            'mechanisms' => ['security_key' => [
                'enabled' => true,
                'relying_party_name' => 'Le test',
            ]],
        ], ranged: true, twig: true);
        $this->kernel->boot();

        return $this->kernel;
    }

    private function visit(PolicyTestKernel $kernel, string $path): Response
    {
        $request = Request::create($path);
        $request->headers->set('PHP_AUTH_USER', 'arnaud');
        $request->headers->set('PHP_AUTH_PW', 'secret');

        return $kernel->handle($request, HttpKernelInterface::MAIN_REQUEST, false);
    }
}
