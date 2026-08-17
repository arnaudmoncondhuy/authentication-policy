<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Sous quel pare-feu la requête en cours est traitée.
 *
 * C'est ce qui permet au paquet de ne gouverner que les annuaires qu'on lui a nommés, et donc
 * de laisser l'entrée des machines entièrement hors de son champ.
 *
 * Nul hors de toute requête — une commande, une tâche planifiée — et {@see Perimeter} ne couvre
 * alors rien : ce qui n'est pas situé n'est pas gouverné.
 */
interface Firewall
{
    public function name(): ?string;
}
