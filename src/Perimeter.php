<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Les pare-feux d'humains auxquels ce paquet s'applique.
 *
 * Une application tient souvent deux annuaires : les personnes d'un côté, les machines de
 * l'autre. Rien de ce que ce paquet garantit n'a de sens pour une machine — elle ne pose pas de
 * second facteur, elle ne choisit pas la durée de sa session, et le verrou d'enrôlement la
 * mettrait dehors sans lui laisser de porte.
 *
 * Nommer les pare-feux concernés met la séparation dans la structure. Une politique qui
 * n'exige rien des machines produit le même résultat, mais par accident : elle cesse de
 * protéger le jour où l'on resserre.
 */
final readonly class Perimeter
{
    /** @param list<string> $firewalls les noms tels que la configuration de sécurité les écrit */
    public function __construct(private array $firewalls)
    {
    }

    /**
     * Un périmètre vide ne couvre rien, et un pare-feu qui n'y figure pas n'est jamais couvert.
     *
     * Le nul se produit hors de toute sécurité — une commande, une tâche planifiée, une
     * application sans pare-feu — et répond faux : couvrir ce qu'on ne sait pas situer
     * reviendrait à verrouiller des surfaces dont on ignore tout.
     */
    public function covers(?string $firewall): bool
    {
        return null !== $firewall && \in_array($firewall, $this->firewalls, true);
    }
}
