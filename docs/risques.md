# Ce que le dispositif couvre, et ce qu'il ne couvre pas

Solide, pas militaire. Le seuil est écrit ici plutôt que sous-entendu : un dispositif dont on
ignore la limite est un dispositif dont on surestime la portée.

## Couvert

| Situation | Ce qui la couvre |
|---|---|
| mot de passe volé ou rejoué | le second facteur, exigé par rôle et impossible à contourner par une porte oubliée |
| poste laissé ouvert | l'inactivité, plafonnée par la configuration |
| session qui ne finit jamais parce qu'on s'en sert tous les jours | la durée absolue, que l'activité ne repousse pas |
| un rôle qui s'accorde plus que le plafond | le repliement, qui ne sait que resserrer |
| un choix personnel qu'on croit enregistré | le refus de compiler sans stockage |
| une page ajoutée sans y penser | le verrou fermé par défaut |
| hameçonnage | seulement si le mécanisme installé est une passkey ; un code à six chiffres se donne au faux site comme au vrai |

## Non couvert

| Situation | Pourquoi |
|---|---|
| attaquant ayant déjà la main sur le serveur | il lit la session et la base ; aucune politique ne s'y oppose |
| poste client compromis | un enregistreur de frappe voit le code, et un navigateur détourné agit dans la session ouverte |
| aspiration de masse par un compte légitime | ce n'est pas de l'authentification : c'est du plafonnement de lecture |
| analyse temporelle, canaux cachés | hors du seuil assumé |
| adversaire étatique | hors du seuil assumé |
| clé de service oubliée dans un script | le paquet ne connaît que les comptes qui ouvrent une session |

## Les limites du dispositif lui-même

**Une passe de compilation ne voit que des services.** Une classe qu'aucun service ne désigne
échappe au contrôle des dispenses. Elle n'est atteinte par aucune requête, donc n'ouvre rien —
mais le contrôle ne prouve pas qu'elle n'existe pas.

**Le verrou juge la porte, pas ce qu'elle fait.** Une dispense posée sur une classe entière
ouvre toutes ses routes. La poser sur la méthode est plus fin, et rien n'y oblige.

**La politique d'une session est celle de son ouverture.** Un resserrement s'applique aux
connexions suivantes ; les sessions en cours gardent leurs durées. Le rattrapage — invalider ce
qui est ouvert — n'est pas ici.

**`Enrollment` est cru sur parole.** Le paquet demande si quelqu'un a posé son second facteur,
il ne vérifie pas la réponse. C'est la seule ligne du dispositif qu'une implémentation
complaisante peut désarmer entièrement.

**Le mécanisme n'est pas vérifié.** Le paquet ne sait pas si `scheb/2fa-bundle` est correctement
branché sur votre pare-feu. Il exige ; c'est le mécanisme qui demande.
