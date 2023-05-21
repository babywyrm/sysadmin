#!/usr/bin/env python

# https://gist.github.com/tigercosmos/a5af5359b81b99669ef59e82839aed60
##
##
##

# coding: utf-8

import numpy as np
import cv2
import os
import math
from cyvlfeat.kmeans import kmeans
from scipy import ndimage
from scipy.spatial import distance
from tqdm import tqdm
import pickle
from cyvlfeat.kmeans import kmeans
from cyvlfeat.sift.dsift import dsift
from libsvm.svmutil import *

"""
Image Hierarchy:

data
- train
  - class1
  - class2
  - ...
- test
  - class1
  - class2
  - ...
"""
def get_images(path, size):
    total_pic = {}
    labels = []
    for i, doc in enumerate(os.listdir(path)):
        tmp = []
        for file in os.listdir(os.path.join(path, doc)):      
            
            if file.endswith(".jpg"):
                img = cv2.imread(os.path.join(path, doc, file), cv2.IMREAD_GRAYSCALE)
                pic = cv2.resize(img, (size, size))
                tmp.append(pic)
                labels.append(i)
        total_pic[doc] = tmp
    return total_pic, labels



# get images with resize
train, train_digit_labels = get_images('./data/train/', 256)
test, test_digit_labels = get_images('./data/test/', 256)


# visual_words
def sift_features(images, size):
    print("feature number", size)

    bag_of_features = []
    print("Extract SIFT features...")
    for key, value in tqdm(images.items()):
        for img in value:
            # orb = cv2.xfeatures2d.SIFT_create(500)
            # orb = cv2.ORB_create()
            # keypoints, descriptors = orb.detectAndCompute(img, None)
            _, descriptors = dsift(img, step=[5,5], fast=True)
            if descriptors is not None:
                for des in descriptors:
                    bag_of_features.append(des)
    
    print("Compute kmeans in dimensions:", size)
    
    km = kmeans(np.array(bag_of_features).astype('float32'), size, initialization="PLUSPLUS")    

    return km


features = sift_features(train, size=15)


def image_class(images, features):
    image_feats = []
    print("Construct bags of sifts...")
    
    for key, value in tqdm(images.items()):
        empty = [0 for i in range(0, len(features))]
        
        for img in value:
            # orb = cv2.ORB_create()
            # orb = cv2.xfeatures2d.SIFT_create()
            # keypoints, descriptors = orb.detectAndCompute(img, None)
            _, descriptors = dsift(img, step=[5,5], fast=True)
            if descriptors is not None:
                dist = distance.cdist(features, descriptors, metric='euclidean')
                
                idx = np.argmin(dist, axis=0) 
                hist, bin_edges = np.histogram(idx, bins=len(features))
                hist_norm = [float(i)/sum(hist) for i in hist]
                image_feats.append(hist_norm)
            else:
                print("NONE")
                image_feats.append(empty)
        
    image_feats = np.asarray(image_feats)
    return image_feats


bovw_train = image_class(train, features) 
bovw_test = image_class(test, features) 


def nearest_neighbor_classify(train_image_feats, train_labels, test_image_feats, K=50):
    dist = distance.cdist(test_image_feats, train_image_feats, metric='euclidean')
    
    test_predicts = []
    
    for test in dist:
        label_count = {}
        for key in train.keys():
            label_count[key] = 0

        idx = np.argsort(test)
        for i in range(K):
            cat = train_labels[idx[i]]
            label_count[cat] += 1
        

        final = ""
        max_value = 0
        for key in label_count:
            if label_count[key] > max_value:
                final = key
                max_value = label_count[key]
                
        test_predicts.append(final)
    
    return test_predicts


# In[112]:


train_labels = np.array([item for item in train.keys() for i in range(100)])
test_labels = np.array([item for item in test.keys() for i in range(10)])
knn = nearest_neighbor_classify(bovw_train, train_labels, bovw_test)


# In[114]:


def accuracy(results, test_labels):
    num_correct = 0
    for i, res in enumerate(results):
        if res == test_labels[i]:
            num_correct += 1
    return num_correct / len(results)

print("Bag of SIFT representation & nearest neighbor classifier \nAccuracy score: {:.1%}".format(accuracy(knn, test_labels)))

# -e: tolerance of termination criterion
# -t 0: linear kernel
# -c: parameter C of C-SVC
m = svm_train(train_digit_labels, bovw_train, '-c 700 -e 0.0001 -t 0')
p_label, p_acc, p_val = svm_predict(test_digit_labels, bovw_test, m)

print("Bag of SIFT representation and linear SVM classifier\nAccuracy score: {:.1%}".format(p_acc))

##
##
