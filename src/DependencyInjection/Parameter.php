<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

/**
 * Les paramètres que le bundle pose et que les passes relisent.
 *
 * Rassemblés ici plutôt que sur l'une des passes : plusieurs lecteurs partagent ces noms, et
 * les loger chez l'un d'eux ferait dépendre les autres d'une classe dont ils n'ont rien à
 * savoir.
 */
final class Parameter
{
    /**
     * La politique déclarée, sous une forme que le conteneur compilé sait porter : un tableau,
     * et non l'objet. C'est ce que relisent les passes, qui s'exécutent après l'extension.
     *
     * @see PolicyFactory pour la forme exacte
     */
    public const string RULES = 'authentication_policy.rules';

    /** Le chemin où le verrou renvoie ce qui n'a pas encore posé son second facteur. */
    public const string ENROLLMENT_PATH = 'authentication_policy.enrollment_path';

    /**
     * Ce que la famille des réglages sans bouton donne à voir : les durcissements qui ne
     * dépendent pas de ce paquet, et dont l'absence ne se constate qu'en lisant la
     * configuration du framework.
     *
     * Rempli à la compilation parce qu'une commande n'a plus accès au conteneur de
     * construction, et lu par `authentication-policy:doctor`.
     */
    public const string FINDINGS = 'authentication_policy.findings';

    /** Les marques désignant des portes, en plus de celles que le framework pose. */
    public const string EXTRA_SURFACE_TAGS = 'authentication_policy.surface_tags';

    /** La politique peut-elle exiger un second facteur de quelqu'un. */
    public const string TWO_FACTOR_REQUIRABLE = 'authentication_policy.two_factor_requirable';

    /** Le service qui range les codes de secours, ou null pour celui du paquet. */
    public const string BACKUP_CODES_STORE = 'authentication_policy.backup_codes.store';

    /** Le cadre dont les écrans du paquet héritent, ou null pour celui du paquet. */
    public const string LAYOUT = 'authentication_policy.layout';

    /** Créer la table des codes de secours au premier usage. */
    public const string BACKUP_CODES_AUTO_SETUP = 'authentication_policy.backup_codes.auto_setup';

    private function __construct()
    {
    }
}
