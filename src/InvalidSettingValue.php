<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Une valeur stockée n'est pas du type de son réglage.
 *
 * Une durée reçue en chaîne de caractères, une exigence reçue en entier : la source est
 * toujours un stockage que le paquet ne gouverne pas. Le refus est immédiat plutôt que
 * converti, parce qu'une conversion silencieuse décide à la place de l'application — `"0"`
 * deviendrait une session de durée nulle, et personne n'entrerait plus.
 */
final class InvalidSettingValue extends \InvalidArgumentException
{
}
