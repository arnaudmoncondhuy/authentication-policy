<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Mechanism\BackupCodes;

use ArnaudMoncondhuy\AuthenticationPolicy\Bridge\Visitor;
use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Factors;
use ArnaudMoncondhuy\AuthenticationPolicy\LastFactorRemoval;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * L'écran des codes de secours : les poser, les lire une fois, les retirer.
 *
 * Les codes ne sont lisibles qu'au moment où ils viennent d'être posés, et ne repassent jamais
 * par la session ni par une redirection : quitter la page, c'est les avoir perdus. C'est ce qui
 * fait qu'on les note.
 */
#[DuringEnrollment('On y pose son premier moyen : le verrou doit laisser passer.')]
final readonly class BackupCodesController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_backup_codes';

    public function __construct(
        private BackupCodes $backupCodes,
        private Factors $factors,
        private Visitor $visitor,
        private Environment $twig,
        private UrlGeneratorInterface $urls,
        private ?CsrfTokenManagerInterface $csrf,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->visitor->identifier();

        if (!$request->isMethod('POST')) {
            return $this->render($user, null);
        }

        $this->requireCsrf($request);

        if ('discard' === $request->request->get('geste')) {
            try {
                $this->backupCodes->discardFor($user);
            } catch (LastFactorRemoval $refus) {
                return $this->render($user, null, $refus->getMessage());
            }

            return new RedirectResponse($this->urls->generate($this->backupCodes->manageAt()));
        }

        return $this->render($user, $this->backupCodes->generateFor($user));
    }

    /**
     * @param list<string>|null $codes ce qui vient d'être posé, et qui ne sera plus jamais lisible
     */
    private function render(string $user, ?array $codes, ?string $error = null): Response
    {
        $posed = $this->backupCodes->countFor($user);

        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'codes' => $codes,
            'restants' => $posed,
            'autres_moyens' => $this->factors->countFor($user) - $posed,
            'erreur' => $error,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]));
    }

    private function requireCsrf(Request $request): void
    {
        if (null === $this->csrf) {
            return;
        }

        if (!$this->csrf->isTokenValid(new CsrfToken(self::CSRF_TOKEN_ID, (string) $request->request->get('_token')))) {
            throw new AccessDeniedException('Jeton de sécurité invalide.');
        }
    }
}
