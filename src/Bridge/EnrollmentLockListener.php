<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use ArnaudMoncondhuy\AuthenticationPolicy\DuringEnrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\Enrollment;
use ArnaudMoncondhuy\AuthenticationPolicy\PolicyResolver;
use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;

/**
 * Le verrou : tant que la politique exige un second facteur que quelqu'un n'a pas posé, aucune
 * surface ne lui répond.
 *
 * **Fermé par défaut.** C'est toute la garantie, et c'est ce qui la distingue d'une obligation
 * qu'on poserait porte par porte : une route ajoutée demain est verrouillée sans que personne
 * y pense, parce que personne n'a eu à y penser. Ce qui doit rester joignable pendant
 * l'enrôlement porte {@see DuringEnrollment}, et une passe de compilation refuse une dispense
 * posée là où elle ne produirait rien.
 *
 * Se branche sur la résolution du contrôleur et non sur la requête : c'est le premier moment où
 * l'on sait quelle classe va répondre, donc le premier où la dispense est lisible. Le
 * contrôleur n'est pas encore appelé.
 *
 * Ce qui ne le concerne pas, et qu'il laisse passer sans rien lire : les sous-requêtes, les
 * requêtes sans compte connecté, et tout ce dont la politique n'exige rien — un pare-feu de
 * machines, par exemple, dont les comptes n'ont pas de second facteur à poser.
 */
final readonly class EnrollmentLockListener
{
    public function __construct(
        private PolicyResolver $resolver,
        private TokenStorageInterface $tokens,
        private Enrollment $enrollment,
        private string $enrollmentPath,
    ) {
    }

    public function __invoke(ControllerEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $token = $this->tokens->getToken();

        if (null === $token) {
            return;
        }

        $identifier = $token->getUserIdentifier();

        if (!$this->resolver->decideFor($identifier, ...$token->getRoleNames())->requires(Setting::TwoFactor)) {
            return;
        }

        if ($this->enrollment->isCompleteFor($identifier)) {
            return;
        }

        // La dispense est cherchée sur la méthode d'abord : une porte peut n'ouvrir qu'une de
        // ses routes, et la poser sur la classe entière ouvrirait les autres avec elle.
        if ($this->isExempt($event) || $this->leadsToEnrollment($event)) {
            return;
        }

        $event->setController(fn (): RedirectResponse => new RedirectResponse($this->enrollmentPath));
    }

    private function isExempt(ControllerEvent $event): bool
    {
        return [] !== $event->getAttributes(DuringEnrollment::class);
    }

    /**
     * Le garde-fou contre la boucle.
     *
     * Le chemin d'enrôlement doit rester joignable même si la dispense n'a pas été posée
     * dessus : sans cela, le verrou renverrait vers une page qu'il verrouille, et le navigateur
     * rendrait une erreur de redirection en boucle plutôt que la page qui débloque.
     */
    private function leadsToEnrollment(ControllerEvent $event): bool
    {
        return str_starts_with($event->getRequest()->getPathInfo(), $this->enrollmentPath);
    }
}
