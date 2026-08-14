# Montage

Le paquet s'installe sans qu'on écrive quoi que ce soit, et n'exige alors rien de personne. Ce
qui suit est ce qu'on ajoute quand on veut qu'il serve.

## 1. Écrire la politique

```yaml
# config/packages/authentication_policy.yaml
authentication_policy:
    enrollment_path: /profil/second-facteur

    settings:
        two_factor:
            ceiling: false
            delegated_to: [role, user]

        idle_timeout:
            ceiling: 28800
            delegated_to: [role, user]

        absolute_timeout:
            ceiling: 2592000

        remember_me:
            ceiling: true
            delegated_to: [role]
```

`ceiling` est le **point de départ**, pas une valeur par défaut qu'on remplace : les niveaux
délégués ne savent que resserrer. Absent, il vaut la valeur la plus permissive — ce qu'une passe
refuse pour une durée déléguée, faute de quoi le rôle deviendrait la politique.

Un réglage absent de ce fichier reste ouvert. Il n'a pas besoin d'y figurer pour exister :
`authentication-policy:policy` les affiche tous.

## 2. Implémenter ce que la politique délègue

Trois contrats, aucun stockage imposé. Le conteneur refuse de compiler si la politique délègue
sans que le contrat correspondant soit branché — **il faut donc l'aliaser**, l'autowiring ne
devine pas une interface.

```php
final readonly class DoctrineRolePolicies implements RolePolicies
{
    public function __construct(private RolePolicyRepository $rows)
    {
    }

    public function valuesFor(string $role): array
    {
        return $this->rows->findOneByRole($role)?->settings() ?? [];
    }
}
```

**Un rôle à la fois** : quelqu'un qui en porte trois ferait autrement arbitrer votre code entre
trois valeurs d'un même réglage. Ici la question ne se pose pas — le résolveur garde la plus
stricte, quel que soit l'ordre.

```yaml
# config/services.yaml
services:
    ArnaudMoncondhuy\AuthenticationPolicy\RolePolicies: '@App\Security\DoctrineRolePolicies'
    ArnaudMoncondhuy\AuthenticationPolicy\UserPreferences: '@App\Security\DoctrineUserPreferences'
    ArnaudMoncondhuy\AuthenticationPolicy\Enrollment: '@App\Security\TotpEnrollment'
```

Les clés rendues sont les identités des réglages — `two_factor`, `idle_timeout` — et les valeurs
leur nature : un booléen, ou un nombre de secondes strictement positif. Une identité inconnue ou
une valeur du mauvais type **arrête la résolution**, bruyamment. C'est voulu : une préférence
silencieusement écartée est une préférence qu'on croit appliquée.

## 3. Ouvrir ce qui doit rester joignable

Le verrou est fermé par défaut. Trois pages, en général, et rarement plus :

```php
#[DuringEnrollment('Affiche le QR code et enregistre le secret partagé.')]
final class TwoFactorEnrollmentController
{
}

#[DuringEnrollment('Rend les codes de secours, qu\'il faut avoir avant de pouvoir entrer.')]
final class BackupCodesController
{
}
```

La déconnexion n'a pas besoin de dispense : elle est traitée par le pare-feu, qui répond avant
qu'un contrôleur soit résolu.

Le chemin d'enrôlement lui-même reste joignable même sans dispense — sinon le verrou renverrait
vers une page qu'il verrouille, et le navigateur rendrait une erreur de boucle plutôt que la
page qui débloque.

## 4. L'écran de profil

`CurrentDecisions` rend la politique appliquée à qui est connecté. Rien à recalculer, rien à
redécider :

```php
public function __invoke(CurrentDecisions $decisions): Response
{
    return $this->render('profil/securite.html.twig', [
        'reglages' => $decisions->all(),
    ]);
}
```

```twig
{% for decision in reglages %}
    <li>
        {{ decision.setting.value }} :
        {% if decision.locked %}
            <em>{{ decision.explanation }}</em>
        {% else %}
            {# le champ, et sa valeur courante #}
        {% endif %}
    </li>
{% endfor %}
```

`decisions.ignored()` est vide dans le cas courant. Non vide, il porte les choix qu'une personne
a faits et que la politique n'écoute plus : les afficher comme s'ils portaient encore serait le
seul mensonge que le paquet ne peut pas empêcher tout seul.

## 5. Les comptes de service

Un pare-feu de machines n'a pas de second facteur à poser. Deux choses à tenir :

- ne pas exiger `two_factor` de leurs rôles — c'est le cas courant, puisqu'on l'exige d'un rôle
  humain nommé ;
- si un doute subsiste, faire répondre `true` à `Enrollment::isCompleteFor()` pour eux.

Le verrou ne lit rien d'une requête sans compte connecté, et les durées de session ne
s'appliquent qu'aux connexions qui ouvrent une session.

## 6. Vérifier

```
php bin/console authentication-policy:policy --role=ROLE_ADMIN
php bin/console authentication-policy:doctor
```

Le docteur échoue tant que les durcissements natifs qu'il relève ne sont pas posés. Sa place est
dans votre routine qualité, pas dans une lecture ponctuelle.
