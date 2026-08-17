<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes;

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
 * L'étape de connexion par un code de secours.
 *
 * Sans elle, les codes existent, s'impriment, se comptent — et n'ouvrent rien. C'est le seul
 * moment où ils servent, et il ne se voit qu'en ayant tout perdu.
 *
 * Le rendu du formulaire est porté par la même classe : le mécanisme et son écran de
 * vérification se lisent ensemble, et rien d'autre ne les emploie.
 */
final readonly class BackupCodesAtLogin implements TwoFactorProviderInterface, TwoFactorFormRendererInterface
{
    public function __construct(
        private BackupCodes $backupCodes,
        private Perimeter $perimeter,
        private ExitDoor $exit,
        private Environment $twig,
        private string $template,
        private ?string $layout,
    ) {
    }

    /**
     * L'étape n'est proposée qu'à qui a des codes, et sur un pare-feu confié au paquet : le nom
     * vient du contexte, sans avoir à situer la requête.
     */
    public function beginAuthentication(AuthenticationContextInterface $context): bool
    {
        return $this->perimeter->covers($context->getFirewallName())
            && $this->backupCodes->countFor($context->getUser()->getUserIdentifier()) > 0;
    }

    public function needsPreparation(): bool
    {
        return false;
    }

    public function prepareAuthentication(object $user): void
    {
    }

    /**
     * Le compte n'est connu que par son identité : rien n'est demandé à l'entité de
     * l'application, qui n'a donc rien à implémenter pour que ce mécanisme fonctionne.
     */
    public function validateAuthenticationCode(object $user, string $authenticationCode): bool
    {
        return $user instanceof UserInterface
            && $this->backupCodes->consume($user->getUserIdentifier(), $authenticationCode);
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
