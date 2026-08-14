<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Dispense une porte du verrou d'enrôlement, avec la raison qui la justifie.
 *
 * Le verrou est **fermé par défaut** : tant que quelqu'un n'a pas posé ce que la politique
 * exige de lui, aucune surface ne lui répond. C'est l'inversion qui fait tenir la garantie —
 * une porte ajoutée demain est fermée sans que personne y pense, là où une obligation à poser
 * classe par classe s'oublie.
 *
 * Il faut donc rouvrir ce qui doit rester joignable pendant l'enrôlement, et à peu près rien
 * d'autre : la page qui enrôle, celle qui montre les codes de secours, la déconnexion. Chaque
 * dispense est une ligne du verrou en moins, et c'est pourquoi la raison est obligatoire — elle
 * s'écrit une fois et se relit à chaque revue.
 *
 *     #[DuringEnrollment('Affiche le QR code du second facteur.')]
 *     final class EnrollmentController
 *     {
 *     }
 *
 * Se pose sur la classe d'une porte — contrôleur, commande, consommateur de message — ou sur
 * l'une de ses méthodes. Une dispense posée ailleurs, sur une classe qu'aucune requête
 * n'atteint, arrête la compilation : elle donnerait le sentiment d'une porte ouverte là où il
 * n'y en a pas, et masquerait celle qu'on croyait avoir rouverte.
 */
#[\Attribute(\Attribute::TARGET_CLASS | \Attribute::TARGET_METHOD)]
final readonly class DuringEnrollment
{
    public function __construct(public string $reason)
    {
        if ('' === trim($reason)) {
            throw new \InvalidArgumentException('Une dispense du verrou d\'enrôlement s\'accompagne de sa raison.');
        }
    }
}
