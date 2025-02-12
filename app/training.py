import pandas as pd
import numpy as np
import pickle
import sklearn.ensemble as ske
from sklearn import tree, linear_model
from sklearn.model_selection import train_test_split
from sklearn.feature_selection import SelectFromModel
from sklearn.externals import joblib
from sklearn.naive_bayes import GaussianNB
from sklearn.metrics import confusion_matrix
from sklearn.utils import shuffle
import os

def AI_Trainer(dataset, classifier_file, feature_file):
    data = pd.read_csv(dataset, sep='|')
    X = data.drop(['Name', 'md5', 'legitimate'], axis=1).values
    y = data['legitimate'].values

    print('Researching important feature based on %i total features\n' % X.shape[1])

    # Feature selection using Trees Classifier
    fsel = ske.ExtraTreesClassifier().fit(X, y)
    model = SelectFromModel(fsel, prefit=True)
    X_new = model.transform(X)
    nb_features = X_new.shape[1]

    X_new, y = shuffle(X_new, y, random_state=0)

    X_train, X_test, y_train, y_test = train_test_split(X_new, y ,test_size=0.2)

    features = []

    print('%i features identified as important:' % nb_features)

    indices = np.argsort(fsel.feature_importances_)[::-1][:nb_features]
    for f in range(nb_features):
        print("%d. feature %s (%f)" % (f + 1, data.columns[2+indices[f]], fsel.feature_importances_[indices[f]]))

    # XXX : take care of the feature order
    for f in sorted(np.argsort(fsel.feature_importances_)[::-1][:nb_features]):
        features.append(data.columns[2+f])


    #Algorithm comparison
    algorithms = {
            #"DecisionTree": tree.DecisionTreeClassifier(max_depth=10),
            "RandomForest": ske.RandomForestClassifier(n_estimators=100,criterion='entropy',max_features="auto"),
            #"GradientBoosting": ske.GradientBoostingClassifier(n_estimators=100,max_features="log2"),
            #"AdaBoost": ske.AdaBoostClassifier(n_estimators=100),
            #"GNB": GaussianNB()
        }

    results = {}
    print("\nNow testing algorithms")
    for algo in algorithms:
        clf = algorithms[algo]
        clf.fit(X_train, y_train)
        score = clf.score(X_test, y_test)
        print("%s : %f %%" % (algo, score*100))
        results[algo] = score

    winner = "RandomForest" #max(results, key=results.get)
    print('\nWinner algorithm is %s with a %f %% success' % (results[winner], results[winner]*100))

    # Save the algorithm and the feature list for later predictions
    print('Saving algorithm and feature list in classifier directory...')
    joblib.dump(algorithms[winner], classifier_file)
    open(feature_file, 'wb').write(pickle.dumps(features))
    print('Saved')
 
    # Identify false and true positive rates
    clf = algorithms[winner]
    res = clf.predict(X_test)
    mt = confusion_matrix(y_test, res)
    print("False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100))
    print('False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100)))

def train():
    dataset=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'dataset.csv')
    classifier=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'classifier/classifier.pkl')
    features=os.path.join(os.path.dirname(os.path.realpath(__file__)), 'classifier/feature.pkl')
    
    AI_Trainer(dataset, classifier, features)


if __name__ == "__main__":
    train()