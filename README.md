# arnaudmoncondhuy/authentication-policy

À quel point faut-il prouver que c'est bien soi. La politique se déclare une fois, le paquet
fabrique les moyens de la tenir, et le conteneur refuse de compiler ce qui la contournerait.

```yaml
# config/packages/authentication_policy.yaml
authentication_policy:
    firewalls: [main]
    enrollment_path: /securite

    mechanisms:
        totp:
            enabled: true
            issuer: Mon application
```

Trois lignes de plus dans l'application, et rien d'autre :

```yaml
# config/packages/security.yaml — dans le pare-feu concerné
            two_factor:
                auth_form_path: authentication_policy_login
                check_path: authentication_policy_login_check
```
```yaml
# config/routes.yaml
authentication_policy:
    resource: .
    type: authentication_policy
```

Aucune classe à écrire, aucun gabarit à copier, aucune table à migrer. Les écrans, l'étape de
connexion, le rangement et le comportement du navigateur viennent du paquet.

## Ce que le paquet garantit

Sept garanties, et chacune arrête la compilation du conteneur — pas la requête, pas le test :
la compilation, y compris sur le poste de qui vient de l'écrire.

| Ce qui est refusé | Pourquoi ça ne se verrait pas autrement |
|---|---|
| Un verrou qui peut se fermer sans chemin de sortie ni mécanisme allumé | Le premier compte concerné n'atteint plus aucune page, souvent un administrateur |
| Un niveau délégué sans stockage | L'écran propose un choix, personne ne l'enregistre, et la valeur retombe en silence |
| Une durée déléguée sans plafond | Le niveau délégué devient la politique |
| Un paquet qui gouverne sans périmètre, ou nomme un pare-feu inexistant | Tout paraît en place et rien ne s'applique |
| Un moyen d'authentification venu d'ailleurs | Le paquet garantirait un compte protégé par un mécanisme dont il ne sait rien |
| Un mécanisme allumé que rien ne réclame à la connexion | Les moyens se posent, se comptent, ouvrent le verrou — et personne ne les demande |
| Un écran qui retire un moyen sans jeton pour le protéger | Une page visitée ailleurs peut périmer une série de codes |

Une huitième chose se rapporte sans se refuser : les durcissements natifs absents — limitation
des tentatives, attributs du cookie de session — que `authentication-policy:doctor` relève parce
que rien d'autre ne les signale.

## Le périmètre : ce paquet ne gouverne que ce qu'on lui nomme

Une application tient souvent deux annuaires : les personnes d'un côté, les machines de l'autre.
Rien de ce que ce paquet promet n'a de sens pour une machine — elle ne pose pas de second
facteur, ne choisit pas la durée de sa session, et le verrou la mettrait dehors sans porte.

`firewalls` nomme les pare-feux des personnes. Ce qui n'y figure pas échappe à tout, **par
construction** : une politique qui n'exigerait rien des machines produirait le même résultat,
mais par accident — et cesserait de protéger le jour où on la resserre.

## Un niveau ne peut que resserrer

Trois niveaux parlent, dans cet ordre : la configuration, le rôle, la personne. Chacun ne peut
que resserrer ce que le précédent a posé — ce n'est pas une consigne, la résolution ne sait pas
faire l'inverse.

```yaml
    settings:
        two_factor:
            ceiling: false             # non exigé par défaut…
            delegated_to: [role, user] # …mais un rôle ou la personne peut l'exiger

    role_policies:
        ROLE_ADMIN:
            two_factor: true           # validé à la compilation, avec le nom du rôle fautif
```

Ce qui est retenu n'est pas ce qui s'applique : un choix plus large que le plafond reste rangé
tel quel, et la résolution le ramène — c'est ce qui permet de desserrer la politique plus tard
sans redemander à chacun ce qu'il voulait.

## Le verrou, et sa seule échappatoire

Tant que la politique exige un second facteur que quelqu'un n'a pas posé, **aucune surface ne
lui répond**. Fermé par défaut : une route ajoutée demain est verrouillée sans que personne y
pense, parce que personne n'a eu à y penser.

Ce qui doit rester joignable pendant l'enrôlement le déclare :

```php
#[DuringEnrollment('Affiche le QR code du second facteur.')]
final class SecondFactorController { }
```

Une dispense posée là où elle ne produirait rien — sur une classe qui n'est pas une porte
d'entrée — arrête la compilation.

## Les mécanismes

Trois, livrés entiers, éteints tant qu'on ne les allume pas :

| Mécanisme | Ce qu'il apporte |
|---|---|
| `totp` | Le code à six chiffres d'une application d'authentification. QR code si `endroid/qr-code` est là, secret en toutes lettres sinon. Un secret non confirmé ne compte pas. |
| `security_key` | Clé physique, empreinte, visage, code de l'appareil — une seule norme. Le comportement du navigateur vient du paquet. |
| `backup_codes` | Dix codes à noter, pour entrer quand tout le reste est perdu. Un code ne sert qu'une fois. |

**Aucun ne se remplace.** Une application ne peut pas apporter le sien : ce qui compte comme
protection est vérifié par ce qui l'a écrit. Ce qui se remplace, c'est l'apparence et le
rangement.

```yaml
    mechanisms:
        security_key:
            enabled: true
            relying_party_name: Mon application   # obligatoire : le navigateur refuse sans
            relying_party_id: '%env(WEBAUTHN_RP_ID)%'
            store: 'App\Security\NosCles'         # facultatif : le rangement du projet
```

Un mécanisme allumé range dans une table préfixée que le paquet crée au premier usage. Là où le
compte de base de données n'a pas à posséder le schéma, `storage.auto_setup: false` rend la main
aux migrations du projet, et `doctor` dit ce qui manque.

⚠️ Le préfixe des tables doit être exclu du filtre de schéma de l'application, faute de quoi
`doctrine:migrations:diff` proposera de **supprimer** ce qu'aucune entité ne décrit :

```yaml
# config/packages/doctrine.yaml
        schema_filter: '~^(?!authentication_)~'
```

## Un écran, tous les moyens

`/securite` montre ce qui protège le compte, ce qui lui manque, et la durée de ses sessions.
Aucun mécanisme n'y est nommé : l'écran affiche ce que les moyens installés déclarent.

Deux voies de surcharge, cumulables. La clé `templates.<écran>` nomme un autre gabarit ; un
fichier du même nom dans `templates/bundles/AuthenticationPolicyBundle/` en remplace un sans rien
configurer. La clé l'emporte quand les deux existent. Les chemins se décident de même :

```yaml
    routes:
        prefix: /mon-compte
        security_key: /mes-cles
```

## Installation

```bash
composer require arnaudmoncondhuy/authentication-policy
```

Pas de recette Flex ; le type `symfony-bundle` suffit. Le paquet s'installe sans configuration :
chaque réglage garde alors sa valeur la plus permissive, aucun mécanisme n'existe, rien ne
change.

Selon ce qu'on allume : `scheb/2fa-bundle` (dès qu'un mécanisme est allumé),
`spomky-labs/otphp` (code à six chiffres), `web-auth/webauthn-lib` (clés), `doctrine/dbal` (le
rangement du paquet), `endroid/qr-code` (le QR code plutôt que le secret en toutes lettres),
`symfony/stimulus-bundle` (le comportement des clés, qui arrive alors sans une ligne à écrire).

## Les deux commandes

`authentication-policy:policy` affiche la politique résolue, avec l'option `--role` pour la voir
telle qu'un rôle la subit.

`authentication-policy:doctor` examine l'installation : le périmètre, les mécanismes allumés, le
verrou, les stockages, et les durcissements natifs absents. Elle **échoue** plutôt que d'afficher
— une routine qualité ne peut s'appuyer que sur un code de sortie.

## Les réglages

| Réglage | Nature | Appliqué par |
|---|---|---|
| `two_factor` | exigence | le paquet |
| `backup_codes` | exigence | le projet |
| `trusted_device` | permission | le projet |
| `remember_me` | permission | le projet |
| `idle_timeout` | durée | le paquet |
| `absolute_timeout` | durée | le paquet |

L'énumération est fermée : un réglage qu'une application ajouterait échapperait aux garanties.

## Ce qui reste au projet

Son entité de comptes, ses pare-feux, et les trois lignes de configuration ci-dessus. Rien
d'autre.

Ce que le paquet ne peut pas faire à sa place est écrit dans `docs/ce-qui-reste-au-projet.md` —
notamment : **supprimer un compte n'efface pas ce que ce paquet range sous son identité**, et
recréer le même identifiant lui rendrait les moyens de l'ancien. Le service `Oblivion` et la
commande `authentication-policy:forget` existent pour cela.

## Compatibilité

PHP 8.4+, Symfony 7.3+ et 8.x. Le contrat n'a aucune dépendance hors Symfony et PSR-20 ; les
mécanismes apportent les leurs, et ne sont montés que s'ils sont allumés.

## Version

**0.x — le paquet marche, il n'est pas éprouvé.** Tant que le numéro commence par un zéro, la
surface publique peut bouger.

Deux conditions pour le 1.0 : avoir tourné dans deux applications réelles, et que chacune ait
reversé sa règle enfreinte dans `docs/ce-qui-reste-au-projet.md`.
