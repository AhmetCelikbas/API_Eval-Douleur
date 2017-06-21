# API_Eval-Douleur
API REST pour un hôpital fictif
Des équipes soignantes doivent évaluer et suivre l'évolution de la douleur des patients

### Règles principales :
- Les administrateurs peuvent créer des médecins et des infirmiers
- Les administrateurs peuvent créer des types d'évaluations
- Les docteurs peuvent créer des patients
- Les docteurs peuvent créer et modifier des évlauations
- Les infirmiers peuvent créer et modifier des évaluations
- Les patients peuvent s'autoévaluer
- Il existe plusieurs types d'évaluations
- Une évaluation en cours peut être reprise
- Une évaluation sera considérée comme une suite de 7 entiers de 1 à 10

### Authentification :
- PHP-JWT : [**https://github.com/firebase/php-jwt**](https://github.com/firebase/php-jwt)

### Installation :
#### Dépendances :
``` bash
composer install
```

#### Base de données :
- Importer le code SQL du fichier database/eval-douleur.sql sur votre SGBD MySQL
- Créer un compte administrateur manuellement dans la table utilisateur en insérant un enregistrement avec un champ fonction ayant pour valeur 'administrateur'

```SQL
INSERT INTO utilisateur VALUES ( NULL, 'username', 'password', 'nom', 'prenom', 'administrateur', '2017-06-21')
```

