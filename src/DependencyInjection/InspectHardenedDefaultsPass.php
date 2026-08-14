<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\DependencyInjection;

use ArnaudMoncondhuy\AuthenticationPolicy\Setting;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Relève les durcissements qui ne se règlent pas, et dont l'absence ne se voit nulle part.
 *
 * Cette passe ne refuse rien : ce qu'elle examine n'appartient pas au paquet. La limitation des
 * tentatives et les attributs du cookie de session sont natifs, ils se posent en trois lignes,
 * et leur absence est silencieuse — aucune page ne casse, aucun test ne rougit, rien ne s'écrit
 * dans un journal. C'est précisément ce qui les fait oublier.
 *
 * Le relevé se fait ici parce que ces réponses ne sont lisibles qu'au moment de construire le
 * conteneur : une commande, plus tard, n'a plus accès à ce qui a été déclaré. Elle le range
 * dans un paramètre, et `authentication-policy:doctor` le rend.
 */
final readonly class InspectHardenedDefaultsPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        $findings = [
            ...$this->aboutTheSessionCookie($container),
            ...$this->aboutLoginThrottling($container),
            ...$this->aboutTheRealSessionLifetime($container),
        ];

        $container->setParameter(Parameter::FINDINGS, $findings);
    }

    /**
     * Les attributs du cookie qui porte la session.
     *
     * `cookie_secure` vaut « auto » par défaut chez Symfony, ce qui suffit : le cookie devient
     * sûr dès que la requête l'est. Seul un `false` explicite est un choix, et c'est celui-là
     * qu'on relève.
     *
     * @return list<string>
     */
    private function aboutTheSessionCookie(ContainerBuilder $container): array
    {
        if (!$container->hasParameter('session.storage.options')) {
            return [];
        }

        /** @var array<string, mixed> $options */
        $options = (array) $container->getParameter('session.storage.options');
        $findings = [];

        if (false === ($options['cookie_secure'] ?? 'auto')) {
            $findings[] = 'Le cookie de session est déclaré non sûr (`framework.session.cookie_secure: false`) : '
                .'il voyagera en clair sur une requête non chiffrée.';
        }

        if (false === ($options['cookie_httponly'] ?? true)) {
            $findings[] = 'Le cookie de session est lisible par le JavaScript de la page '
                .'(`framework.session.cookie_httponly: false`).';
        }

        // `??` ne conviendrait pas : il confondrait la clé absente, qui vaut « lax », avec le nul
        // explicite, qui est justement le relâchement qu'on cherche.
        $samesite = \array_key_exists('cookie_samesite', $options) ? $options['cookie_samesite'] : 'lax';

        if (null === $samesite || 'none' === $samesite) {
            $findings[] = 'Le cookie de session accompagne les requêtes venues d\'autres sites '
                .'(`framework.session.cookie_samesite`) : c\'est ce dont vit la falsification de requête.';
        }

        // Un cookie ne connaît pas le port : deux applications servies par la même adresse se
        // partagent le pot, et celle qui écrit en dernier a raison.
        if ('PHPSESSID' === ($options['name'] ?? \ini_get('session.name'))) {
            $findings[] = 'Le cookie de session porte le nom par défaut (`framework.session.name`) : '
                .'toute autre application servie par la même adresse écrase la session de celle-ci, '
                .'quel que soit le port — et le nom annonce à lui seul par quoi le site est servi.';
        }

        return $findings;
    }

    /**
     * La durée que le stockage des sessions accorde, comparée à celle que la politique annonce.
     *
     * `session.gc_maxlifetime` vaut 1440 secondes par défaut, et un gestionnaire qui range les
     * sessions ailleurs que dans des fichiers s'en sert pour les purger.
     *
     * @return list<string>
     */
    private function aboutTheRealSessionLifetime(ContainerBuilder $container): array
    {
        if (!$container->hasParameter('session.storage.options') || !$container->hasParameter(Parameter::RULES)) {
            return [];
        }

        /** @var array<string, mixed> $options */
        $options = (array) $container->getParameter('session.storage.options');

        /** @var array<string, array{ceiling?: bool|int|null, delegated_to?: list<string>}> $rules */
        $rules = $container->getParameter(Parameter::RULES);

        $announced = PolicyFactory::fromArray($rules)->ruleFor(Setting::IdleTimeout)->ceiling;
        $granted = $options['gc_maxlifetime'] ?? \ini_get('session.gc_maxlifetime');

        if (!\is_int($announced) || \PHP_INT_MAX === $announced || !is_numeric($granted)) {
            return [];
        }

        $granted = (int) $granted;

        if ($granted >= $announced) {
            return [];
        }

        return [\sprintf(
            'La politique annonce %d secondes sans activité, mais le stockage des sessions n\'en accorde que %d '
            .'(`framework.session.gc_maxlifetime`) : la session tombe avant, sans que rien ne l\'explique.',
            $announced,
            $granted,
        )];
    }

    /**
     * La limitation des tentatives de connexion.
     *
     * Le service n'existe que si un pare-feu l'a demandée. Aucun ne l'ayant fait, le mot de
     * passe se devine à la vitesse du réseau.
     *
     * @return list<string>
     */
    private function aboutLoginThrottling(ContainerBuilder $container): array
    {
        if (!$container->hasParameter('security.firewalls')) {
            return [];
        }

        /** @var list<string> $firewalls */
        $firewalls = (array) $container->getParameter('security.firewalls');

        foreach ($firewalls as $firewall) {
            if ($container->has(\sprintf('security.login_throttling.%s.limiter', $firewall))) {
                return [];
            }
        }

        return [] === $firewalls ? [] : [
            'Aucun pare-feu ne limite les tentatives de connexion (`security.firewalls.*.login_throttling`) : '
            .'un mot de passe s\'y essaie sans frein.',
        ];
    }
}
