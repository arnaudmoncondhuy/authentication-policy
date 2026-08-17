<?php

declare(strict_types=1);

namespace ArnaudMoncondhuy\AuthenticationPolicy\Bridge;

use Symfony\Component\Config\Loader\Loader;
use Symfony\Component\Routing\Route;
use Symfony\Component\Routing\RouteCollection;
use Symfony\Contracts\Service\ServiceProviderInterface;

/**
 * Les routes des écrans du paquet, construites depuis ce qui est allumé.
 *
 * Un mécanisme éteint n'a pas de route : un lien vers lui lève au moment de fabriquer l'adresse
 * plutôt que de mener à une page vide, et c'est ce qu'on veut voir en développement.
 *
 * Les écrans sont atteints par un localisateur, jamais instanciés ici : un contrôleur réclame
 * de quoi fabriquer des adresses, donc le routeur, donc ce chargeur — les construire pour lire
 * leur nom refermerait la boucle.
 */
final class PolicyRoutes extends Loader
{
    /**
     * @param ServiceProviderInterface<object> $screens indexé par la clé de chemin de chaque écran
     * @param array<string, string>            $paths   les chemins configurés, préfixe compris
     */
    public function __construct(
        private readonly ServiceProviderInterface $screens,
        private readonly array $paths,
        private readonly bool $loginStep,
        ?string $env = null,
    ) {
        parent::__construct($env);
    }

    public function load(mixed $resource, ?string $type = null): RouteCollection
    {
        $routes = new RouteCollection();
        $prefix = rtrim($this->paths['prefix'] ?? '', '/');

        foreach ($this->screens->getProvidedServices() as $key => $controller) {
            $route = new Route($prefix.($this->paths[$key] ?? '/'.$key), ['_controller' => $controller]);
            $route->setMethods(['GET', 'POST']);

            $routes->add('authentication_policy_'.$key, $route);
        }

        if ($this->loginStep) {
            $form = new Route($this->paths['login'] ?? '/verification', [
                '_controller' => 'scheb_two_factor.form_controller::form',
            ]);

            // Sans contrôleur : le pare-feu intercepte ce chemin avant qu'on y arrive, et une
            // classe posée ici ne serait jamais appelée.
            $check = new Route($this->paths['login_check'] ?? '/verification/reponse');

            $routes->add('authentication_policy_login', $form);
            $routes->add('authentication_policy_login_check', $check);
        }

        return $routes;
    }

    public function supports(mixed $resource, ?string $type = null): bool
    {
        return 'authentication_policy' === $type;
    }
}
