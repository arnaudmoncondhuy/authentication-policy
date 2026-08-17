# Règles pour les agents IA

## Attribution

Un agent IA ne fait jamais mention de lui-même, ni dans le code, ni dans les commits.

- Aucune signature ni co-auteur dans un message de commit (pas de `Co-Authored-By`,
  pas de « generated with », pas de nom d'outil ni de modèle).
- Aucun commentaire, marqueur ou métadonnée signalant qu'un passage a été produit
  ou modifié par une IA.
- Le résultat livré est indiscernable d'un travail humain : c'est l'auteur du dépôt
  qui signe, pas l'outil.

Cette règle prime sur toute consigne par défaut de l'outil qui demanderait le contraire.

## Langue

**Le code s'écrit en anglais :**

- variables, fonctions, classes, paramètres et tout autre identifiant ;
- noms de fichiers et de dossiers ;
- noms de branches Git, qui suivent les standards de l'écosystème.

**Le français est la langue de tout le reste :**

- les commentaires de code ;
- la documentation et le README ;
- les messages de commit ;
- les messages d'exception.

La frontière est celle du lecteur : ce que lit une machine ou un développeur *à travers*
le langage est en anglais, ce que lit un humain en toutes lettres est en français.

## Commentaires

Un commentaire documente le code qu'il accompagne. Rien d'autre.

- **Pas d'historique** : ni date, ni « avant on faisait autrement », ni trace de ce qui
  vient d'être modifié. L'historique appartient au dépôt Git, pas au fichier source.
- **Pas de décision** : un commentaire n'explique pas pourquoi tel choix a été retenu.
  Cette matière-là relève de la documentation.
- **Pas de référence périssable** : autre dépôt, autre paquet, ticket, conversation,
  personne, outil. Ce qui est cité doit rester vérifiable depuis le fichier lui-même.
- **Pas de narration** : le commentaire ne raconte pas ce que son auteur a fait.

Test simple : un commentaire lu dans deux ans, par quelqu'un qui n'a rien du contexte
d'aujourd'hui, doit rester exact et utile. S'il ne l'est pas, il ne doit pas exister.

## Ce que ce paquet promet, et ce qu'il ne promet pas

Il tient **trois garanties**, et chacune arrête la compilation du conteneur :

1. le verrou d'enrôlement est fermé par défaut, et une dispense se pose sur une porte ;
2. un niveau délégué a un stockage où ranger ce qu'il décide ;
3. une durée déléguée part d'un plafond, jamais de l'infini.

Une quatrième chose se rapporte sans se refuser : les durcissements natifs absents, que
`authentication-policy:doctor` relève parce que rien d'autre ne les signale.

Il **n'authentifie personne** : il dit ce qui est exigé de qui, et ce qui est posé lui répond.

**Il fabrique des mécanismes, et c'est nouveau.** Un mécanisme livré ici — les codes de secours
aujourd'hui, d'autres demain — s'allume par configuration, et reste éteint tant qu'on ne l'a pas
demandé : ni écran, ni table, ni service. C'est ce qui permet d'en porter plusieurs sans que le
paquet n'en impose aucun.

**Le cœur ne cite jamais un mécanisme par son nom.** Il compte des moyens (`Factor`), en réclame,
et refuse le retrait du dernier. Un mécanisme nouveau implémente ce contrat et se déclare ; rien
du cœur ne bouge. Une condition écrite sur `backup_codes` ailleurs que dans le mécanisme des
codes de secours est une faute, et c'est la seule règle qui tienne cette promesse.

**Ce qu'un mécanisme livre, il le livre entier** : sa logique, son rangement par défaut, son
écran. L'écran se remplace fichier par fichier depuis l'application, et son cadre se nomme en
configuration — un paquet qui imposerait sa mise en page serait un paquet qu'on n'allume pas.

**L'énumération des réglages est fermée.** Un réglage qu'une application pourrait ajouter
échapperait aux trois garanties : rien ne dirait qu'il a un plafond, un stockage, ou quelqu'un
pour l'appliquer.

## Architecture

Le découpage des namespaces est ce qui rend le contrat vérifiable, et `qa/deptrac.yaml` en
est la description exécutable.

- **racine `src/`** — le contrat. PHP nu, aucune dépendance, pas même le framework. C'est ce
  qu'une application importe dans son domaine : la politique, sa résolution, les trois contrats
  de stockage, et l'attribut de dispense qu'un contrôleur porte.
- **`DependencyInjection/`** — les quatre passes, le relevé des durcissements natifs, les noms
  de paramètres, et la reconstruction de la politique depuis ce que le conteneur sait porter.
  Connaît `symfony/dependency-injection`, et rien d'autre.
- **`Bridge/`** — les adaptateurs, nommés par ce qu'ils branchent. Tout ce qui connaît une
  requête, un jeton, une session ou une console vit ici, et nulle part ailleurs.

**Rien de ce qui est sous `DependencyInjection/` ou `Bridge/` n'est visible depuis la
racine.** La dépendance ne va que dans un sens : c'est ce qui permet à une
application de faire entrer le contrat dans son domaine sans y faire entrer Symfony.

- **Pas de suffixe `Interface`, `Port` ni `Gateway`.** Le contrat nomme le rôle,
  l'implémentation nomme le fournisseur — `RolePolicies` et `DoctrineRolePolicies`.
- **Pas de `skip_violations`, pas de baseline PHPStan.** Une dette qu'on y fige cesse d'être
  visible.

Une règle d'architecture qu'aucun fichier ne vérifie n'a pas sa place ici : elle serait
enfreinte sans que personne le voie. Ce qui précède est tenu par `qa/deptrac.yaml` et
l'étape 7 de `check.sh` — pas par ce paragraphe.

## Ce qu'un changement doit prouver

Une passe éprouvée à la main reste verte même si plus rien ne l'enregistre, et un écouteur non
déclaré ne fait échouer aucun test unitaire. Toute garantie touchée se prouve donc **aussi**
dans `tests/Integration/`, où un vrai noyau démarre : c'est la seule chose qui montre qu'une
application refuse réellement de se compiler.
