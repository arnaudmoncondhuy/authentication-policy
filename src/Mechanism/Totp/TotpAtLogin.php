<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\Totp;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\ExitDoor;
use ArnaudMoncondhuy\AuthenticationPolicy\Perimeter;
use Scheb\TwoFactorBundle\Security\TwoFactor\AuthenticationContextInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorFormRendererInterface;
use Scheb\TwoFactorBundle\Security\TwoFactor\Provider\TwoFactorProviderInterface;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\User\UserInterface;
use Twig\Environment;

/**
 * L'étape de connexion par le code à six chiffres.
 *
 * Le compte n'est connu que par son identité : rien n'est demandé à l'entité de l'application,
 * qui n'a donc aucune interface à implémenter pour que ce mécanisme fonctionne.
 */
final readonly class TotpAtLogin implements TwoFactorProviderInterface, TwoFactorFormRendererInterface
{
    public function __construct(
        private Totp $totp,
        private Perimeter $perimeter,
        private ExitDoor $exit,
        private Environment $twig,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        return $this->perimeter->covers($context->getFirewallName())
            && $this->totp->countFor($context->getUser()->getUserIdentifier()) > 0;
    }

    public function needsPreparation(): bool
    {
        return false;
    }

    public function prepareAuthentication(object $user): void
    {
    }

    public function validateAuthenticationCode(object $user, string $authenticationCode): bool
    {
        return $user instanceof UserInterface
            && $this->totp->verifyFor($user->getUserIdentifier(), $authenticationCode);
    }

    public function getFormRenderer(): TwoFactorFormRendererInterface
    {
        return $this;
    }

    public function renderForm(Request $request, array $templateVars): Response
    {
        return new Response($this->twig->render($this->template, [
            ...$templateVars,
            'layout' => $this->layout,
            'sortie' => $this->exit->path(),
        ]));
    }
}
