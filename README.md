# arnaudmoncondhuy/authentication-policy

À quel point faut-il prouver que c'est bien soi. La politique se déclare **une fois**, le
conteneur refuse de compiler ce qui la contournerait, et le verrou d'enrôlement est **fermé par
défaut**.

```yaml
# config/packages/authentication_policy.yaml
authentication_policy:
    enrollment_path: /profil/second-facteur

    settings:
        two_factor:
            ceiling: false          # personne n'y est tenu d'office…
            delegated_to: [role, user]   # …mais un rôle peut l'exiger, et chacun peut se l'imposer

        idle_timeout:
            ceiling: 28800          # huit heures, et jamais davantage
            delegated_to: [role, user]   # un rôle peut écourter, une personne encore

        remember_me:
            ceiling: true
            delegated_to: [role]    # un rôle peut l'interdire, jamais le rétablir
```

Le paquet **n'authentifie personne** : Symfony et `scheb/2fa-bundle` le font. Il décide ce qui
est exigé de qui, et empêche d'oublier la réponse au projet suivant.

## Ce que le paquet garantit

Trois règles, et chacune **arrête la compilation du conteneur**. Pas un contrôle d'intégration
continue qu'on peut contourner : l'application ne démarre pas, y compris sur le poste de qui a
écrit la faute.

| Règle | Ce qu'elle empêche |
|---|---|
| **Le verrou est fermé par défaut** | la page atteinte sans avoir posé le second facteur qu'un rôle exige — y compris celle qu'on écrira demain, puisque personne n'a rien à y déclarer |
| **Une dispense se pose sur une porte** | la dispense qui n'ouvre rien, et laisse croire qu'une page reste joignable pendant l'enrôlement |
| **Un verrou qui se ferme a une sortie** | l'application fermée à ses propres administrateurs, sans page d'enrôlement où les envoyer |
| **Ce qui est délégué a un stockage** | le champ qu'un écran de profil affiche, que quelqu'un règle, et que rien n'enregistre |
| **Une durée déléguée a un plafond** | le rôle qui pose trente jours là où on croyait avoir écrit huit heures |

Une quatrième chose ne se refuse pas et se rapporte : `authentication-policy:doctor` relève les
durcissements natifs absents — limitation des tentatives, attributs du cookie de session. Aucun
ne casse quoi que ce soit par son absence, et c'est bien le problème.

## Un niveau ne peut que resserrer

La configuration parle, puis les rôles, puis la personne. **Cette règle n'est pas un contrôle
qu'on pourrait retirer : elle est indisponible.** Chaque nature de réglage sait replier deux
valeurs en gardant la plus stricte, et il n'existe aucun chemin de code qui remonte.

| Nature | Plus strict veut dire | Exemple |
|---|---|---|
| exigence | vrai | `two_factor`, `backup_codes` |
| permission | faux | `trusted_device`, `remember_me` |
| durée | court | `idle_timeout`, `absolute_timeout` |

Conséquence directe : plusieurs rôles portés par la même personne se replient au plus strict,
**quel que soit leur ordre**. Le contrat interroge un rôle à la fois précisément pour que cet
arbitrage n'appartienne jamais au projet.

## Ce qu'une décision porte

Une valeur seule oblige l'écran à redevenir la politique. `Decision` porte les trois choses
qu'un écran de profil demande :

```php
$decision = $decisions->of(Setting::IdleTimeout);

$decision->seconds();       // 28800
$decision->decidedBy;       // Decider::Role
$decision->locked;          // false — on peut encore écourter
$decision->explanation();   // « Décidé par le rôle, et vous pouvez encore resserrer. »
```

Sans `decidedBy`, une case grisée n'a pas d'explication — et c'est là que naît la douleur :
quelqu'un qui ne comprend pas pourquoi il ne peut rien changer finit par demander qu'on lui
ouvre.

## Le verrou, et sa seule échappatoire

Tant que la politique exige un second facteur que quelqu'un n'a pas posé, **aucune surface ne
lui répond**. Ce qui doit rester joignable le déclare, avec sa raison :

```php
#[DuringEnrollment('Affiche le QR code du second facteur.')]
final class EnrollmentController
{
}
```

La raison est obligatoire : chaque dispense est une ligne du verrou en moins, et elle se relit à
chaque revue. Posée ailleurs que sur une porte — contrôleur, commande, consommateur de message —
elle arrête la compilation.

## Ce que le paquet ne fait pas

**Il ne stocke rien.** Trois contrats, que le projet implémente comme il veut — Doctrine, un
fichier, un annuaire distant, une clé Redis. Le paquet ne le saura jamais.

| Contrat | Ce qu'il répond |
|---|---|
| `RolePolicies` | ce que l'administration a posé sur **un** rôle |
| `UserPreferences` | ce qu'une personne a choisi pour elle-même |
| `Enrollment` | si quelqu'un a posé ce que la politique exige de lui |

**Il fabrique les mécanismes qu'on lui demande, et aucun autre.** Les codes de secours sont
livrés avec le paquet — logique, rangement, écran — et restent éteints tant que la configuration
ne les allume pas. Le second facteur par application ou par clé reste au mécanisme installé, qui
se déclare au paquet pour être compté. `authentication-policy:doctor` distingue explicitement ce
que le paquet applique de ce qu'il se contente de résoudre — sans quoi on croit tenu ce qui ne
l'est pas.

**Le cœur ne connaît que des moyens, jamais leurs noms.** Il en compte, en exige, et refuse le
retrait du dernier : un compte qui n'a plus rien à présenter ne se dépanne depuis aucun écran.

**Il ne couvre pas l'aspiration de masse.** Une identité légitime qui extrait cent mille dossiers
ne relève pas de l'authentification. C'est du plafonnement de lecture, et c'est ailleurs.

**Il ne décide pas qui a le droit de changer un réglage.** C'est de l'autorisation, et les deux
paquets restent indépendants.

## Les codes de secours

Le filet : de quoi entrer quand tout le reste est perdu. Dix codes, chacun bon une fois, rendus
une seule fois à l'écran — après quoi seule leur empreinte subsiste.

```yaml
authentication_policy:
    backup_codes:
        enabled: true
        layout: 'base.html.twig'   # votre cadre ; absent, le paquet en fournit un nu
```

```yaml
# config/routes.yaml
authentication_policy:
    resource: '@AuthenticationPolicyBundle/config/routes.php'
```

Rien d'autre : la table se crée au premier usage, l'écran est monté, et le retrait de la série
est refusé tant qu'elle est le dernier moyen d'entrer. Pour ranger les codes ailleurs, nommez
votre service dans `store` ; pour tenir la table vous-même, coupez `auto_setup`.

## Installation

```bash
composer require arnaudmoncondhuy/authentication-policy
```

Pas de recette Flex, mais le type `symfony-bundle` suffit : Flex enregistre seul le bundle dans
`config/bundles.php`.

**Le paquet s'installe sans qu'on écrive quoi que ce soit.** Sans configuration, chaque réglage
garde sa valeur la plus permissive, aucun verrou ne se ferme, et rien ne change. Ce qui est
exigé l'est parce qu'on l'a écrit.

Le montage complet — les trois contrats, l'écran de profil, le compte de service — est dans
[docs/montage.md](docs/montage.md).

## Les deux commandes

```
authentication-policy:policy --role=ROLE_ADMIN
```

Ce que la configuration déclare, et ce qu'un rôle reçoit une fois la résolution jouée. Sans
elle, connaître la politique d'un rôle demande de lire un fichier, une table, et de replier les
deux de tête — faisable une fois, jamais à chaque revue.

```
authentication-policy:doctor
```

Le verrou et sa sortie, les stockages branchés, ce qui est résolu ici mais appliqué par le
projet, et les durcissements natifs absents. **Elle échoue** plutôt que d'afficher : une routine
qualité ne peut s'appuyer que sur ce qui rend un code de sortie.

## Les réglages

| Réglage | Nature | Appliqué par |
|---|---|---|
| `two_factor` | exigence | le paquet — c'est le verrou |
| `idle_timeout` | durée | le paquet |
| `absolute_timeout` | durée | le paquet |
| `backup_codes` | exigence | le projet |
| `trusted_device` | permission | le projet |
| `remember_me` | permission | le projet |

L'énumération est fermée. Un paquet qui laisserait ajouter des réglages ne pourrait plus rien
garantir sur eux — ni qu'ils ont un plafond, ni qu'ils ont un stockage, ni que quelqu'un les
applique.

## Ce qui reste au projet

Le paquet livre le mécanisme, jamais les garanties d'ensemble : le journal des connexions, la
liste des sessions actives, l'expiration des clés de service, l'écran de profil et celui
d'administration vous appartiennent. La liste tenue à jour est dans
[docs/ce-qui-reste-au-projet.md](docs/ce-qui-reste-au-projet.md), et
[docs/risques.md](docs/risques.md) dit ce que le dispositif couvre et ce qu'il ne couvre pas.

## Compatibilité

PHP 8.4+, Symfony 7.3+ et 8.x. Aucune dépendance hors Symfony et PSR-20.

## Version

**0.x — le paquet marche, il n'est pas éprouvé.** La distinction n'est pas de la modestie.
Depuis le 17/08/2026, il tourne dans une première application réelle, avec de vrais comptes et
deux mécanismes de second facteur branchés derrière — une application d'authentification et des
clés. Il en manque une seconde, et c'est elle qui dira ce qui ne se voit pas d'ici.

Tant que le numéro commence par un zéro, **la surface publique peut bouger** — les six contrats
compris. Deux conditions pour le 1.0, et pas une de moins :

- avoir tourné dans **deux applications réelles**, avec un mécanisme de second facteur branché ;
- que chacune ait reversé sa règle enfreinte dans
  [docs/ce-qui-reste-au-projet.md](docs/ce-qui-reste-au-projet.md).

C'est cette seconde condition qui compte. Un paquet correct devient un paquet qui prévient le
jour où il a vu quelqu'un se tromper pour de bon.
