import os
import json
import random
import numpy as np
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

"""
Usage:
1) Prepare a CSV or JSON dataset with the same feature schema used in the extension.
   Feature order (matching popup.js extractMlFeatures):
   [bias(ignored), isHttps, hasCsp, hasMixed, hasXfo, hasHsts, xctoNosniff,
    hasReferrer, hasPerm, hasCoop, hasCorp, suspiciousScripts, cryptoMining,
    malwareFlags, sensitiveAutocomplete, passwordInputIssues, insecureCookies,
    externalReq]
   Target: risk label (0 = safe, 1 = risky) or continuous risk in [0,1].

2) Train:
   python train_model.py --data path/to/data.json --out_dir ../model

3) Convert to TFJS (after training):
   pip install tensorflowjs
   tensorflowjs_converter --input_format=tf_saved_model \
       --signature_name=serving_default --saved_model_tags=serve \
       ../model/saved_model ../model/tfjs

   Or for Keras .h5:
   tensorflowjs_converter --input_format=keras ../model/model.h5 ../model/tfjs

4) Copy ../model/tfjs/* into the extension's model directory and ensure manifest
   exposes them via web_accessible_resources.
"""

import argparse

def load_dataset(path):
    with open(path, 'r', encoding='utf-8') as f:
        if path.endswith('.json'):
            data = json.load(f)
        else:
            raise ValueError('Only JSON dataset supported in this template')
    X = []
    y = []
    for row in data:
        features = row['features']  # length 18 as above (bias can be omitted)
        if len(features) == 19:
            features = features[1:]
        elif len(features) == 18:
            pass
        else:
            raise ValueError(f'Unexpected feature length: {len(features)}')
        X.append(features)
        y.append(row['label'])
    X = np.array(X, dtype=np.float32)
    y = np.array(y, dtype=np.float32)
    return X, y


def build_model(input_dim: int) -> keras.Model:
    inputs = keras.Input(shape=(input_dim,), name='features')
    x = layers.Normalization(name='norm')(inputs)
    # Simple, small model for on-device inference
    x = layers.Dense(32, activation='relu')(x)
    x = layers.Dropout(0.2)(x)
    x = layers.Dense(16, activation='relu')(x)
    outputs = layers.Dense(1, activation='sigmoid', name='risk')(x)
    model = keras.Model(inputs=inputs, outputs=outputs)
    model.compile(optimizer=keras.optimizers.Adam(1e-3),
                  loss='binary_crossentropy',
                  metrics=['AUC'])
    return model


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--data', required=True)
    parser.add_argument('--out_dir', default=os.path.join('..', 'model'))
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)

    X, y = load_dataset(args.data)

    model = build_model(X.shape[1])

    # Fit normalization layer
    norm_layer = model.get_layer('norm')
    norm_layer.adapt(X)

    callbacks = [
        keras.callbacks.EarlyStopping(patience=5, restore_best_weights=True),
    ]

    model.fit(X, y, validation_split=0.2, epochs=50, batch_size=64, callbacks=callbacks)

    # Save Keras and SavedModel
    keras_path = os.path.join(args.out_dir, 'model.h5')
    model.save(keras_path)
    saved_model_dir = os.path.join(args.out_dir, 'saved_model')
    tf.saved_model.save(model, saved_model_dir)

    # Save feature schema for the extension
    schema = {
        "order": [
            "isHttps", "hasCsp", "hasMixed", "hasXfo", "hasHsts",
            "xctoNosniff", "hasReferrer", "hasPerm", "hasCoop", "hasCorp",
            "suspiciousScripts", "cryptoMining", "malwareFlags",
            "sensitiveAutocomplete", "passwordInputIssues", "insecureCookies",
            "externalReq"
        ]
    }
    with open(os.path.join(args.out_dir, 'feature_schema.json'), 'w', encoding='utf-8') as f:
        json.dump(schema, f, indent=2)

    print('Saved:', keras_path, 'and', saved_model_dir)


if __name__ == '__main__':
    main()



