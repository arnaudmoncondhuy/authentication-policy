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

    /** Les pare-feux d'humains auxquels le paquet s'applique. */
    public const string FIREWALLS = 'authentication_policy.firewalls';

    /** Ce que la configuration pose sur les rôles, indexé par nom de rôle. */
    public const string ROLE_POLICIES = 'authentication_policy.role_policies';

    /** Le préfixe commun des tables que le paquet range. */
    public const string TABLE_PREFIX = 'authentication_policy.storage.table_prefix';

    /** L'alias sous lequel le rangement trouve la connexion à employer. */
    public const string CONNECTION = 'authentication_policy.storage.connection';

    /**
     * Le préfixe des rangements : `…store.backup_codes` et ses voisins.
     *
     * Un alias par mécanisme, que la configuration fait pointer ailleurs. C'est ce qui permet
     * au point de montage de brancher le rangement d'une application sans nommer une seule
     * classe de mécanisme.
     */
    public const string STORE = 'authentication_policy.store';

    /** Créer les tables du paquet au premier usage. */
    public const string AUTO_SETUP = 'authentication_policy.storage.auto_setup';

    /**
     * Le préfixe des gabarits : un paramètre par écran, `…template.security` et ses voisins.
     *
     * Un paramètre par écran plutôt qu'un tableau : c'est ce qu'un fichier de services sait
     * injecter dans un argument, sans passer par une expression.
     */
    public const string TEMPLATE = 'authentication_policy.template';

    /** Le chemin de chaque route, indexé par le nom de la route. */
    public const string ROUTES = 'authentication_policy.routes';

    /** Le réglage de chaque mécanisme, indexé par son nom. Ce que relisent les passes. */
    public const string MECHANISMS = 'authentication_policy.mechanisms';

    /**
     * Le préfixe des réglages d'un mécanisme : `…mechanism.totp.issuer` et ses voisins.
     *
     * Un paramètre par réglage en plus du tableau ci-dessus : c'est ce qu'un fichier de
     * services sait injecter dans un argument.
     */
    public const string MECHANISM = 'authentication_policy.mechanism';

    /** L'étape de second facteur est-elle montée : un mécanisme allumé, et de quoi la poser. */
    public const string LOGIN_STEP = 'authentication_policy.login_step';

    /**
     * Au-delà de combien de secondes une preuve d'identité cesse d'être récente.
     *
     * Ne concerne que les actes qui l'exigent : une session ordinaire ne redemande rien, et
     * c'est ce qui permet de la choisir courte sans rendre le travail pénible.
     */
    public const string PROOF_FRESHNESS = 'authentication_policy.proof.freshness';
    public const string ATTEMPTS_MAX = 'authentication_policy.attempts.max';
    public const string ATTEMPTS_INTERVAL = 'authentication_policy.attempts.interval';

    private function __construct()
    {
    }
}
