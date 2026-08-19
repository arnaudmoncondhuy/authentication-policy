<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\Challenge;
use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Twig\Environment;

/**
 * L'écran qui redemande un moyen devant un acte qui le mérite.
 *
 * Ce n'est pas une connexion : la session reste ouverte, on ne repart de nulle part, et l'acte
 * attend derrière. C'est aussi ce qui rend cet écran nécessaire — l'étape de connexion de
 * `scheb` ne sait faire entrer, pas confirmer.
 *
 * Il ne nomme aucun mécanisme : il affiche ce que les moyens posés sur ce compte déclarent
 * savoir redemander, et passe leur question au navigateur sans la lire.
 */
#[DuringEnrollment('Le détour se joue avant que l\'acte n\'ait lieu : le verrou doit laisser passer.')]
final readonly class ReproveController
{
    public const string CSRF_TOKEN_ID = 'authentication_policy_reprove';

    /**
     * @param iterable<Challenge> $challenges les moyens qui savent se faire redemander
     */
    public function __construct(
        private iterable $challenges,
        private Visitor $visitor,
        private ProvenMoment $moment,
        // Absent quand aucun mécanisme n'est allumé : il n'y aurait alors rien à compter.
        private ?AttemptLimiter $attempts,
        private ReturnPath $returnPath,
        private Environment $twig,
        private ?CsrfTokenManagerInterface $csrf,
        private string $template,
        private ?string $layout,
    ) {
    }

    public function __invoke(Request $request): Response
    {
        $user = $this->visitor->identifier();
        $posed = $this->posedBy($user);

        // Aucun moyen à redemander : renvoyer vers l'écran de sécurité serait mentir sur la
        // cause. Ce cas ne se présente que si l'exigence a été posée sur un compte nu, et
        // l'écran doit le dire.
        if ([] === $posed) {
            return $this->render($user, null, [], null);
        }

        $chosen = $this->chosen($posed, (string) $request->query->get('moyen'));

        if (!$request->isMethod('POST')) {
            return $this->render($user, $chosen, $posed, null);
        }

        $this->requireCsrf($request);

        // Un jeton par essai, pris avant de juger : ce qui n'est pas permis n'est pas jugé.
        $patience = $this->attempts?->attempt($user);

        if (null !== $patience) {
            return $this->render($user, $chosen, $posed, 'throttled', $patience);
        }

        if ($chosen->accepts($user, (string) $request->request->get('reponse'))) {
            $this->attempts?->forget($user);
            $this->moment->record();

            return new RedirectResponse($this->returnPath->take());
        }

        return $this->render($user, $chosen, $posed, 'refused');
    }

    /**
     * @param list<Challenge> $posed
     * @param ?string         $error `refused` quand la réponse était fausse, `throttled` quand
     *                               il y en a eu trop
     */
    private function render(string $user, ?Challenge $chosen, array $posed, ?string $error, int $patience = 0): Response
    {
        return new Response($this->twig->render($this->template, [
            'layout' => $this->layout,
            'moyen' => $chosen?->name(),
            // En minutes : une attente en secondes se lit mal et invite à recompter.
            'patience' => (int) ceil($patience / 60),
            // Redemandée à chaque affichage : une demande ne vaut qu'une fois, et la rejouer
            // serait précisément ce qu'elle empêche.
            'question' => $chosen?->question($user),
            'autres' => array_values(array_map(
                static fn (Challenge $challenge): string => $challenge->name(),
                array_filter($posed, static fn (Challenge $challenge): bool => $challenge !== $chosen),
            )),
            'erreur' => $error,
            'csrf_token_id' => self::CSRF_TOKEN_ID,
        ]), null === $chosen ? Response::HTTP_FORBIDDEN : Response::HTTP_OK);
    }

    /** @return list<Challenge> */
    private function posedBy(string $user): array
    {
        $posed = [];

        foreach ($this->challenges as $challenge) {
            if ($challenge->countFor($user) > 0) {
                $posed[] = $challenge;
            }
        }

        return $posed;
    }

    /**
     * Le moyen demandé, ou le premier posé.
     *
     * Un nom inconnu retombe sur le premier plutôt que de refuser : l'adresse est une
     * préférence d'affichage, pas une décision de sécurité — c'est {@see Challenge::accepts()}
     * qui décide, et il ne juge que le compte qu'on lui nomme.
     *
     * @param non-empty-list<Challenge> $posed
     */
    private function chosen(array $posed, string $wanted): Challenge
    {
        foreach ($posed as $challenge) {
            if ($challenge->name() === $wanted) {
                return $challenge;
            }
        }

        return $posed[0];
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
