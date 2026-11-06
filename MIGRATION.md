# Provenance de cette version

## Source et attribution

- Projet : Cassiopée / Cybernet IA, détection d’intrusions dans un réseau SDN.
- Source : [paul.tulliez/cassiopee sur GitLab](https://gitlabense.imtbs-tsp.eu/paul.tulliez/cassiopee).
- Archive fournie : `cassiopee-main.zip`, importée le 6 novembre 2026.
- Branche indiquée par le nom de l’archive : `main`. Le SHA du commit source n’est pas connu.
- SHA-256 de l’archive reçue : `9629a29e4ff1dfc6939e0bb3ffda71c7b5cb2f0893a2631a6931f9d4ff79ef0d`.
- Auteurs indiqués par l’article : **Jihane Belhoussine, Paul Tulliez et Clémence Viviès**.

L’archive ne contient pas de dossier `.git`. L’historique des commits, branches et contributions individuelles n’a donc pas pu être transféré. Le commit initial de ce dépôt correspond à l’import de la copie collective, et ne revendique pas la création individuelle de tout le projet. Une éventuelle récupération ultérieure de l’historique source devra faire l’objet d’un rapprochement explicite.

## Choix de publication

Les fichiers source et figures retenus ont été conservés depuis l’archive. Seuls le préambule du README et les règles `.gitignore` ont été adaptés pour expliquer cette version. Cette note et le manifeste ont été ajoutés.

Les fichiers suivants restent dans l’archive originale et ne sont pas publiés dans cette copie :

- CSV bruts et préparés, dont plusieurs dépassent 100 Mo ;
- modèle Random Forest sérialisé, encodeur et statistiques de normalisation associées ;
- journaux d’exécution, caches Python, configuration locale de l’éditeur et fichiers de label courant ;
- sorties de compilation de l’article, dont le PDF ; les sources de l’article, la bibliographie et les figures sont conservées.

Le [manifeste de l’import](IMPORT_MANIFEST.json) répertorie les fichiers conservés et exclus, avec les empreintes des fichiers d’origine conservés. L’archive originale n’a pas été modifiée.

## Données et modèle

La génération des observations repose sur un environnement Linux avec Mininet, Open vSwitch et Ryu. Les étapes du projet passent par la génération du trafic, son nettoyage, la préparation des partitions et l’entraînement du modèle.

Dans le code importé, `random_forest.py` lit `data/prepared/train_normalized.csv` et `data/prepared/test_normalized.csv`. Le script `normalize_data.py` prépare les partitions et les statistiques de normalisation. L’entraînement produit `random_forest_model.pkl` et `label_encoder.pkl`, utilisés par le dashboard avec les statistiques associées. Ces fichiers doivent être générés ensemble ; aucun modèle sérialisé n’a été chargé pendant la migration.

Les instructions d’origine mentionnent aussi `network_traffic.csv` : leur cohérence avec le code doit être revue lors de l’audit fonctionnel. Aucun petit jeu de données artificiel n’a été substitué aux données originales pour présenter les résultats existants comme reproduits.

## Vérifications de l’import

- Contrôle des chemins de l’archive avant extraction, et exclusion des fichiers non destinés à la publication.
- Recherche de plusieurs formats de clés API, clés privées, identifiants intégrés dans des URLs et affectations de secrets dans les fichiers texte retenus : aucune correspondance trouvée. Ce contrôle ne garantit pas l’absence de tout élément sensible.
- Analyse syntaxique des 15 fichiers Python, sans les importer ni les exécuter : aucune erreur de syntaxe ; des avertissements d’échappement de chaînes existent avec Python 3.13.
- Aucun entraînement, test fonctionnel, service réseau ou scénario d’attaque n’a été exécuté pendant la migration.

Les graphiques et résultats de l’article sont des livrables existants, non recalculés lors de cet import. Les références bibliographiques et la reproductibilité doivent encore être auditées.

## Conditions d’utilisation

Le README d’origine indique : **« Projet éducatif - Usage académique uniquement. »** Cette mention est conservée. La publication de cette copie de portfolio a été confirmée comme autorisée par Jihane Belhoussine. Aucune licence de redistribution plus large n’est ajoutée et cette publication ne transforme pas le projet en logiciel sous licence MIT ou Apache.
