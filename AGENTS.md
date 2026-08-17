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

Il tient **sept garanties**, et chacune arrête la compilation du conteneur :

1. le verrou d'enrôlement est fermé par défaut, et une dispense se pose sur une porte ;
2. un verrou qui peut se fermer a un chemin de sortie **et** un mécanisme allumé ;
3. un niveau délégué a un stockage où ranger ce qu'il décide ;
4. une durée déléguée part d'un plafond, jamais de l'infini ;
5. ce qui gouverne quelque chose nomme les pare-feux qu'il gouverne, et ceux-ci existent ;
6. aucun moyen d'authentification ne vient d'ailleurs que de ce paquet ;
7. un mécanisme allumé est réclamé à la connexion, et ses écrans de retrait sont protégés.

Une huitième chose se rapporte sans se refuser : les durcissements natifs absents, que
`authentication-policy:doctor` relève parce que rien d'autre ne les signale.

Il **n'authentifie personne** : il dit ce qui est exigé de qui, il fabrique les moyens de le
prouver, et c'est le pare-feu de l'application qui les réclame.

**Il fabrique les mécanismes, et il les impose.** Le code à six chiffres, les clés de sécurité
et les codes de secours vivent ici, entiers. Un mécanisme s'allume par configuration et reste
éteint tant qu'on ne l'a pas demandé : ni écran, ni table, ni service, ni route.

**Un moyen d'authentification n'est pas un point d'extension.** Une application ne peut pas en
apporter un : ce qui compte comme protection est vérifié par ce qui l'a écrit, faute de quoi le
paquet garantirait un compte protégé par un mécanisme dont il ne sait rien. `Factor` est donc
interne, et une passe refuse toute classe qui l'implémente hors d'ici.

**Le cœur ne cite jamais un mécanisme par son nom.** Il compte des moyens, en réclame, et refuse
le retrait du dernier. Une condition écrite sur `backup_codes` ailleurs que dans le mécanisme des
codes de secours est une faute, et c'est la seule règle qui tienne cette promesse.

**Ce qu'un mécanisme livre, il le livre entier** : sa logique, son rangement par défaut, son
écran, son étape de connexion et le comportement que le navigateur exécute. Ce qui se remplace,
c'est l'apparence et le rangement — gabarits, chemins, libellés, service de stockage — jamais la
vérification.

**Le paquet ne gouverne que ce qu'on lui nomme.** Une application tient souvent deux annuaires,
et rien de ce qui est promis ici n'a de sens pour une machine. Ce qui n'est pas dans le périmètre
échappe au verrou, aux durées et aux écrans par construction, et non parce que la politique
n'exigerait rien de lui.

**L'énumération des réglages est fermée.** Un réglage qu'une application pourrait ajouter
échapperait aux garanties : rien ne dirait qu'il a un plafond, un stockage, ou quelqu'un pour
l'appliquer.

## Architecture

Le découpage des namespaces est ce qui rend le contrat vérifiable, et `qa/deptrac.yaml` en
est la description exécutable.

- **racine `src/`** — le contrat. PHP nu, aucune dépendance, pas même le framework. C'est ce
  qu'une application importe dans son domaine : la politique, sa résolution, le périmètre, le
  compte des moyens, les contrats de stockage, et l'attribut de dispense qu'un contrôleur porte.
- **`Storage/`** — le rangement commun : les tables du paquet, leur préfixe, leur venue au
  monde, et de quoi tout oublier d'un compte. Connaît Doctrine ; ne connaît aucun mécanisme.
- **`DependencyInjection/`** — les passes qui refusent, le relevé des durcissements natifs, les
  noms de paramètres, et la reconstruction de la politique depuis ce que le conteneur sait
  porter. Connaît `symfony/dependency-injection`, et rien d'autre.
- **`Bridge/`** — les adaptateurs **du cœur**, nommés par ce qu'ils branchent : le verrou, les
  durées, le pare-feu courant, les routes, les commandes.
- **`Mechanism/<Nom>/`** — un moyen livré entier, une couche par mécanisme. Ce qui connaît une
  technique et ne sert qu'un mécanisme vit avec lui.

**Tout ce qui connaît une technique et sert le cœur vit dans `Bridge/`. Tout ce qui connaît une
technique et sert un seul mécanisme vit avec lui.** Aucun mécanisme n'est visible depuis le
cœur, ni depuis un autre mécanisme.

**Rien de ce qui est sous `DependencyInjection/`, `Bridge/` ou `Mechanism/` n'est visible depuis
la racine.** La dépendance ne va que dans un sens : c'est ce qui permet à une application de
faire entrer le contrat dans son domaine sans y faire entrer Symfony.

**Un dossier neuf sous `src/` échappe à toute règle en silence** : Deptrac n'analyse pas ce
qu'aucune couche ne couvre, et l'analyse reste verte. C'est `debug:unassigned`, joué à l'étape 7,
qui le relève.

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
