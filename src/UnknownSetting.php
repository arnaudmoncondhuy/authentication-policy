<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy;

/**
 * Une valeur stockée désigne un réglage qui n'existe pas.
 *
 * Le cas se produit après avoir renommé ou retiré un cas de {@see Setting} sans reprendre les
 * lignes déjà écrites en base. Le paquet refuse plutôt que d'ignorer : une préférence
 * silencieusement écartée est une préférence qu'on croit appliquée, et c'est exactement ce
 * qu'un paquet censé ne rien laisser oublier ne peut pas se permettre.
 */
final class UnknownSetting extends \InvalidArgumentException
{
}
