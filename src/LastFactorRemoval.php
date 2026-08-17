<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Le retrait demandé laisserait le compte sans aucun moyen de prouver qui il est.
 *
 * La faute ne se voit qu'après coup : le compte reste ouvert jusqu'à la fin de sa session, et
 * c'est à la connexion suivante qu'il découvre qu'on lui demande ce qu'il ne peut plus donner.
 * Personne à ce moment-là ne peut le dépanner depuis l'application.
 */
final class LastFactorRemoval extends \DomainException
{
    public static function of(string $factorName): self
    {
        return new self(\sprintf(
            'Retirer « %s » ne laisserait aucun moyen de se connecter à ce compte, alors que la politique en exige un.',
            $factorName,
        ));
    }
}
