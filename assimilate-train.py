# 
# Assimilate-Train.py
# Copyright 2017 Tim Crothers
# Credit for the excellent Brologreader code is to Mike Sconzo - https://github.com/ClickSecurity/data_hacking/blob/master/browser_fingerprinting/bro_log_reader.py
#

import io
import numpy
from sklearn.externals import joblib
from pandas import DataFrame
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from optparse import OptionParser
from assimilate_utils import BroLogReader

if __name__ == "__main__":

    __version__ = '1.0'
    usage = """assimilate-train [options]"""
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option("-n", "--normaldata", action="store", type="string", \
                      default=None, help="A directory of normal http header logs (required)")
    parser.add_option("-m", "--maliciousdata", action="store", type="string", \
                      default=None, help="A directory of malicious http header logs (required)")
    parser.add_option("-b", "--bayesianfile", action="store", type="string", \
                      default='./nb.pkl', help="the location to store the bayesian classifier")
    parser.add_option("-x", "--vectorizerfile", action="store", type="string", \
                      default='./vectorizers.pkl', help="the location to store the vectorizer")

    (opts, args) = parser.parse_args()
    
    if opts.normaldata == None:
        parser.error('Normal data directory needed')
    
    if opts.maliciousdata == None:
        parser.error('Malicious data directory needed')

    data = DataFrame({'header': [], 'class': []})
    blr = BroLogReader()

    print('Reading normal data...')
    data = data.append(blr.dataFrameFromDirectory(opts.normaldata, 'good'))

    print('Reading malicious data...')
    data = data.append(blr.dataFrameFromDirectory(opts.maliciousdata, 'bad'))

    print('Vectorizing data...')
    vectorizer = CountVectorizer()
    counts = vectorizer.fit_transform(data['header'].values)

    classifier = MultinomialNB()
    targets = data['class'].values
    classifier.fit(counts, targets)

    print('Writing out models...')
    joblib.dump(vectorizer, opts.vectorizerfile)
    joblib.dump(classifier,opts.bayesianfile)

    print('Done!')