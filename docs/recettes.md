# Recettes

## Monter le paquet sans Doctrine

Le paquet ne connaît aucun stockage. Les trois contrats se tiennent en mémoire, en YAML, ou
n'importe où ailleurs — c'est le test de l'agnosticisme, et il tourne dans la suite du paquet.

```php
final readonly class YamlRolePolicies implements RolePolicies
{
    /** @param array<string, array<string, bool|int>> $byRole */
    public function __construct(private array $byRole)
    {
    }

    public function valuesFor(string $role): array
    {
        return $this->byRole[$role] ?? [];
    }
}
```

```yaml
services:
    App\Security\YamlRolePolicies:
        arguments:
            $byRole:
                ROLE_ADMIN: { two_factor: true, idle_timeout: 3600 }

    ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies: '@App\Security\YamlRolePolicies'
```

Une application qui n'a pas de base du tout peut donc exiger un second facteur de ses
administrateurs. Le seul contrat qui suppose une écriture est `Enrollment`, et encore : un
fichier suffit.

## Exiger le second facteur des seuls administrateurs

```yaml
authentication_policy:
    enrollment_path: /profil/second-facteur
    settings:
        two_factor:
            ceiling: false
            delegated_to: [role, user]
```

```php
public function valuesFor(string $role): array
{
    return 'ROLE_ADMIN' === $role ? ['two_factor' => true] : [];
}
```

Un rôle ordinaire ne dit rien et laisse parler le niveau suivant : chacun peut alors se
l'imposer depuis son profil, et personne ne peut se l'ôter s'il est administrateur.

## Ouvrir une porte d'un autre genre

Un outil pour un assistant, un point d'entrée JSON-RPC : le paquet ne connaît que les marques
que Symfony pose. Déclarez la vôtre pour que les dispenses y soient reconnues.

```yaml
parameters:
    authentication_policy.surface_tags: ['app.mcp_tool']
```

## Remplacer l'horloge

Le paquet apporte la sienne pour ne dépendre d'aucun composant qu'une application n'aurait pas
installé. Une application qui a déjà `symfony/clock` remplace l'alias :

```yaml
services:
    Psr\Clock\ClockInterface: '@clock'
```

## Lire la politique sans requête

`PolicyResolver` ne connaît ni session ni jeton : il prend une identité et des noms de rôles.
Une commande, une tâche planifiée ou un test l'appellent directement.

```php
$decisions = $resolver->decideFor('arnaud@exemple.fr', 'ROLE_ADMIN');

$decisions->requires(Setting::TwoFactor);   // true
$decisions->seconds(Setting::IdleTimeout);  // 3600
```

## Afficher pourquoi un champ est verrouillé

```twig
{% set decision = decisions.of(setting) %}

{% if decision.locked %}
    <p class="verrou">{{ decision.explanation }}</p>
{% else %}
    <input name="{{ setting.value }}" value="{{ decision.value }}">
{% endif %}
```

Une case grisée sans explication est ce qui fait demander qu'on la déverrouille.
