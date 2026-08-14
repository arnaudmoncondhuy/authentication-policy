<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Psr\Clock\ClockInterface;

/**
 * L'heure, prise à la source du système.
 *
 * Le paquet déclare la sienne plutôt que d'aller chercher celle du framework : l'horloge de
 * Symfony vit dans un composant séparé, qu'une application n'a pas forcément installé, et un
 * service manquant ne se découvrirait qu'au premier chargement de page.
 *
 * Le contrat reste celui de PSR-20 : une application qui a déjà une horloge la substitue par
 * un simple alias, et les tests posent l'heure qu'ils veulent.
 */
final readonly class SystemClock implements ClockInterface
{
    public function now(): \DateTimeImmutable
    {
        return new \DateTimeImmutable('now');
    }
}
