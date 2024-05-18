"""Module providing a functions to train and use trained model."""
import itertools
import json
import os
import re
import sys
import typing

import joblib
import nltk
import numpy as np
import pandas as pd
from loguru import logger
from sklearn.linear_model import SGDClassifier
from sklearn.model_selection import train_test_split

import settings


class NgramUtils:
    """
    Summary:
        Create, save and load ngrams.
    """

    def __init__(self, ngram_path: str = settings.NGRAM_PATH):
        self.ngram_path = ngram_path

    @logger.catch
    def create_n_gram_combinations(self, ngram_size: int = 3) -> typing.Dict:
        """
        Summary:
            Create all possible ngram combinations from letters and numbers.

        Args:
            ngram_size (int, optional): Size of the ngrams.
            Defaults to 3 - trigram.

        Returns:
            dict: Ngrams. Key - ngram, value - number.
        """
        alphanum = [
            'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm',
            'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z',
            '0', '1', '2', '3', '4', '5', '6', '7', '8', '9'
        ]
        permutations = itertools.product(alphanum, repeat=ngram_size)
        featues_dict = {}
        counter = 0
        for perm in permutations:
            featues_dict[(''.join(perm))] = counter
            counter = counter + 1
        return featues_dict

    @logger.catch
    def get_ngram_combinations(self) -> typing.Dict:
        """
        Summary:
            Get ngrams from file or create it, if file doesn't exist.

        Returns:
            dict: Ngrams. Key - ngram, value - number.
        """
        if os.path.isfile(self.ngram_path):
            with open(self.ngram_path, encoding='utf8') as ng:
                try:
                    ngrams = json.load(ng)
                except json.decoder.JSONDecodeError:
                    ngrams = self.create_n_gram_combinations()
                    self.save_ngram_combinations_from_file(ngrams)
        else:
            ngrams = self.create_n_gram_combinations()
            self.save_ngram_combinations_from_file(ngrams)
        return ngrams

    def save_ngram_combinations_from_file(self, n_grams: typing.Dict):
        """
        Summary:
            Save ngrams to file.

        Args:
            ngrams (dict): Ngrams. Key - ngram, value - number.
        """
        with open(self.ngram_path, "w", encoding='utf8') as file_obj:
            json.dump(n_grams, file_obj, ensure_ascii=False, indent=4)

    @staticmethod
    @logger.catch
    def generate_ngrams_from_string(
        sentence: str,
        ngram_size: int = 3
    ) -> typing.List:
        """
        Summary:
            Generate ngram of specific size from string

        Args:
            sentence (str): sentence from which ngrams will be generated.
            ngram_size (int, optional): Size of the ngrams. Defaults to 3.

        Returns:
            List: Ngrams.
        """
        sentence = sentence.lower()
        sentence = ''.join(e for e in sentence if e.isalnum())
        processed_list = []
        for tup in list(nltk.ngrams(sentence, ngram_size)):
            processed_list.append((''.join(tup)))
        return processed_list


class ModelUtils:
    """
    Summary:
        Train, test, save and load model.
    """
    @staticmethod
    @logger.catch
    def train_model(
        loss: str,
        penalty: str,
        max_iter: int,
        update: bool = False,
    ):
        """
        Summary:
            Full training process.

        Args:
            update (bool, optional): Flag show if model will be trained
            or updated. Defaults to False.
        """
        if update:
            classifier = ModelUtils.load_model()
        else:
            classifier = SGDClassifier(
                loss=loss,
                penalty=penalty,
                max_iter=max_iter
            )
        train_df, test_df = ModelUtils.split_dataframe()
        features_dict = NgramUtils().get_ngram_combinations()
        ModelUtils.insert_data(train_df, classifier, features_dict)
        ModelUtils.save_model(classifier)
        correct, incorrect = ModelUtils.test_model(
            test_df,
            classifier,
            features_dict
        )
        if update:
            print("Model have been updated!")
        else:
            print("Model have been trained!")
        print("Correct Predictions ", correct)
        print("Incorrect Predictions ", incorrect)
        accuracy = (correct / test_df.shape[0]) * 100
        print(f"Accuracy of the model is: {accuracy:.4g} %")

    @staticmethod
    @logger.catch
    def update_model():
        """
        Summary:
            Update model.
        """
        classifier = ModelUtils.load_model()
        dataframe = ModelUtils.load_dataframe()
        features_dict = NgramUtils().get_ngram_combinations()
        ModelUtils.insert_data(dataframe, classifier, features_dict)
        ModelUtils.save_model(classifier)

    @staticmethod
    @logger.catch
    def test_url(
        url: str,
        model_path: str = settings.MODEL_PATH,
        console: bool = False
    ) -> bool:
        """
        Summary:
            Test url.

        Args:
            url (str): url
            model_path (str, optional): path to trained model.
            console (bool, optional): print result to console.
            Defaults to False.

        Returns:
            bool: True if url is malicious, False if url is safe.
        """
        statuses = {True: "URL is Malicious", False: "URL is Safe"}
        classifier = ModelUtils.load_model(model_path)
        features_dict = NgramUtils().get_ngram_combinations()
        url_matrix = UrlUtils.process_url(url, features_dict)
        pred = classifier.predict(url_matrix)
        url_is_malicious = bool(pred[0])
        if console:
            print(statuses.get(url_is_malicious))
        return url_is_malicious

    @staticmethod
    @logger.catch
    def check_model_accuracy():
        """
        Summary:
            Check accuracy of the trained model.
        """
        classifier = ModelUtils.load_model()
        _, test_df = ModelUtils.split_dataframe()
        features_dict = NgramUtils().get_ngram_combinations()
        correct, incorrect = ModelUtils.test_model(
            test_df,
            classifier,
            features_dict
        )
        print("Correct Predictions ", correct)
        print("Incorrect Predictions ", incorrect)
        accuracy = (correct / test_df.shape[0]) * 100
        print(f"Accuracy of the model is: {accuracy:.4g} %")

    @staticmethod
    @logger.catch
    def save_dataframe(
        dataframe: pd.DataFrame,
        dataframe_path: str = settings.DATASET_PATH
    ):
        """
        Summary:
            Save dataframe to file.

        Args:
            dataframe (pd.DataFrame): data, that will be used to train model.
            dataframe_path (str, optional): path, where dataframe
            will be saved. Defaults to settings.DATASET_PATH.
        """
        pd.DataFrame.to_csv(dataframe, dataframe_path, index=False)

    @staticmethod
    @logger.catch
    def split_dataframe(
        test_size: float = 0.2,
        dataset_path: str = settings.DATASET_PATH
    ) -> typing.Tuple:
        """
        Summary:
            Split provided data to train and test dataframes.

        Returns:
            tuple: trand and test dataframes.
        """
        try:
            url_dataframe = pd.read_csv(dataset_path)
        except FileNotFoundError:
            print("Dataframe file not found")
            sys.exit()
        train_df, test_df = train_test_split(
            url_dataframe,
            test_size=test_size
        )
        return train_df, test_df

    @staticmethod
    @logger.catch
    def preprocess_dataset(
        dataframe: pd.DataFrame,
        features_dict: typing.Dict,
    ) -> tuple:
        """
        Summary
            Test trained model

        Args:
            dataframe (pd.DataFrame): dataframe.
            classifier (SGDClassifier): Linear classifiers
            features_dict (typing.Dict): Ngrams. Key - ngram, value - number.

        Returns:
            tuple: Amount of correct and incorrect predictions.
        """
        rows_number = int(settings.ROWS_NUMBER)
        no_of_batches = int(dataframe.shape[0] / rows_number) + 1
        for i in range(0, no_of_batches):
            start = rows_number * i
            if start + rows_number > dataframe.shape[0]:
                batch = dataframe.iloc[start:, :]
            else:
                batch = dataframe.iloc[start:start + rows_number, :]
            batch = batch.reset_index()
            if batch.empty:
                break
            x, y = UrlUtils.preprocess_batch(
                features_dict,
                batch,
                np.zeros([batch.shape[0], len(features_dict)], dtype="int"),
                np.zeros(batch.shape[0], dtype="int")
            )
            yield x, y, batch

    @staticmethod
    @logger.catch
    def insert_data(
        train_dataframe: pd.DataFrame,
        classifier: SGDClassifier,
        features_dict: typing.Dict
    ):
        """
        Summary:
            Insert processed data in the model. Train model.

        Args:
            train_dataframe (pd.DataFrame): test dataframe.
            classifier (SGDClassifier): Linear classifiers
            features_dict (typing.Dict): Ngrams. Key - ngram, value - number.
        """
        for x, y, _ in ModelUtils.preprocess_dataset(
            train_dataframe,
            features_dict
        ):
            classifier.partial_fit(
                x,
                y,
                classes=np.unique(y)
            )

    @staticmethod
    @logger.catch
    def test_model(
        test_dataframe: pd.DataFrame,
        classifier: SGDClassifier,
        features_dict: typing.Dict
    ) -> tuple:
        """
        Summary
            Test trained model

        Args:
            test_dataframe (pd.DataFrame): test dataframe.
            classifier (SGDClassifier): Linear classifiers
            features_dict (typing.Dict): Ngrams. Key - ngram, value - number.

        Returns:
            tuple: Amount of correct and incorrect predictions.
        """
        correct = 0
        incorrect = 0
        for x, _, batch in ModelUtils.preprocess_dataset(
            test_dataframe,
            features_dict
        ):
            y_pred = classifier.predict(x)
            for index, row in batch.iterrows():
                if row['label'] == y_pred[index]:
                    correct += 1
                else:
                    incorrect += 1
        return correct, incorrect

    @staticmethod
    @logger.catch
    def save_model(
        classifier: SGDClassifier,
        file_path: str = settings.MODEL_PATH
    ):
        """
        Summary:
            Save the trained model to a file

        Args:
            classifier (sklearn.linear_model.SGDClassifier): Trained model.
            file_path (str, optional): path to file, where trained model
            will be saved. Defaults to settings.MODEL_PATH.
        """
        joblib.dump(classifier, file_path)

    @staticmethod
    @logger.catch
    def load_model(
        file_path: str = settings.MODEL_PATH
    ) -> SGDClassifier:
        """
        Summary:
            Load the saved model

        Args:
            filename (str, optional): Name of the file with trained model.
            Defaults to 'sgd_model.pkl'.

        Returns:
            sklearn.linear_model.SGDClassifier: Trained model.
        """
        try:
            model = joblib.load(file_path)
            return model
        except FileNotFoundError:
            print('Model file not found')
            sys.exit()

    @staticmethod
    @logger.catch
    def load_dataframe(file_path: str = settings.DATASET_PATH) -> pd.DataFrame:
        """
        Summary:
            Load dataframe from file.

        Args:
            file_path (str, optional): Path to dataframe file.
            Defaults to settings.DATASET_PATH.

        Returns:
            pd.DataFrame: loaded dataframe.
        """
        try:
            dataframe = pd.read_csv(file_path)
            return dataframe
        except FileNotFoundError:
            print('Dataframe file not found')
            sys.exit()


class UrlUtils:
    """
    Summary:
        Process urls.
    """
    @staticmethod
    @logger.catch
    def preprocess_batch(
        features_dict: typing.Dict,
        batch: pd.DataFrame,
        x: np.ndarray,
        y: np.ndarray
    ) -> typing.Tuple[np.ndarray, np.ndarray]:
        """
        Summary:
            Apply vectorization process to current batch.

        Args:
            features_dict (typing.Dict): Ngrams. Key - ngram, value - number.
            batch (pd.DataFrame): current batch of data.
            x (np.ndarray): matrix. Each row is a vector.
            y (np.ndarray): labels vector.

        Returns:
            typing.Tuple: matrix and labels vector.
        """
        for index, row in batch.iterrows():
            url = UrlUtils.clean_url(row['url'])
            for gram in NgramUtils.generate_ngrams_from_string(url):
                try:
                    x[index][features_dict[gram]] = \
                        x[index][features_dict[gram]] + 1
                except KeyError:
                    continue
            y[index] = int(row['label'])
        return x, y

    @staticmethod
    @logger.catch
    def process_url(url: str, features_dict: typing.Dict) -> np.ndarray:
        """
        Summary:
            Apply vectorization process to url.

        Args:
            url (str): url provided by user.
            features_dict (typing.Dict): Ngrams. Key - ngram, value - number.

        Returns:
            np.ndarray: matrix.
        """
        x = np.zeros([1, len(features_dict)], dtype="int")
        url = UrlUtils.clean_url(url)
        for gram in NgramUtils.generate_ngrams_from_string(url):
            try:
                x[0][features_dict[gram]] = x[0][features_dict[gram]] + 1
            except KeyError:
                continue
        return x

    @staticmethod
    @logger.catch
    def clean_url(url: str) -> str:
        """
        Summary:
            clean url of schema and top level domain

        Args:
            url (str): url.

        Returns:
            str: cleaned url
        """
        url = re.sub(r'https?:\/\/', '', url)
        url = re.sub(r'\.[A-Za-z0-9]+\/*', '', url)
        return url
