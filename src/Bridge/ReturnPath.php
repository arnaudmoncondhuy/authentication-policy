<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Où revenir une fois l'identité prouvée à nouveau.
 *
 * Le détour n'a d'intérêt que s'il ramène : renvoyer tout le monde à l'accueil ferait chercher
 * la page qu'on venait de quitter, et découragerait de poser l'exigence là où elle sert.
 *
 * **Seules les lectures sont mémorisées.** Un envoi de formulaire interrompu ne se rejoue pas
 * après coup : le refaire à l'insu de la personne poserait l'acte qu'elle n'a pas confirmé, et
 * c'est exactement l'acte qu'on protégeait. Elle revient à l'écran de sécurité et recommence
 * son geste, en le sachant.
 *
 * Ce qui est retenu est un chemin de cette application, jamais une adresse complète : une
 * adresse mémorisée depuis l'extérieur ferait de cet écran un tremplin vers un autre site.
 */
final readonly class ReturnPath
{
    private const string KEY = 'authentication_policy.return_path';

    /**
     * @param ?string $fallback où revenir à défaut — le chemin d'enrôlement, quand
     *                          l'application en nomme un. Sans lui, la racine : c'est le seul
     *                          chemin dont ce paquet soit sûr qu'il existe
     */
    public function __construct(
        private RequestStack $requests,
        private ?string $fallback,
    ) {
    }

    /** Retient d'où l'on vient, quand cela a un sens. */
    public function remember(Request $request): void
    {
        if (!$request->isMethod('GET')) {
            return;
        }

        $this->requests->getSession()->set(self::KEY, $request->getRequestUri());
    }

    /**
     * Le chemin retenu, et il ne sert qu'une fois : le garder ferait revenir au même endroit
     * la fois suivante, longtemps après que l'acte a été posé.
     */
    public function take(): string
    {
        $session = $this->requests->getSession();

        /** @var ?string $path */
        $path = $session->get(self::KEY);
        $session->remove(self::KEY);

        // Un chemin qui ne commence pas par une seule barre est écarté : `//ailleurs.example`
        // est une adresse absolue pour un navigateur, et le premier caractère est le seul qui
        // les distingue.
        return null !== $path && str_starts_with($path, '/') && !str_starts_with($path, '//')
            ? $path
            : ($this->fallback ?? '/');
    }
}
