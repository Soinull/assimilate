# 
# Assimilate-Assess.py
# Copyright 2017 Tim Crothers
# Credit for the excellent BroLogReader code is to Mike Sconzo - https://github.com/ClickSecurity/data_hacking/blob/master/browser_fingerprinting/bro_log_reader.py
#

import os, io, csv, datetime, itertools
import numpy
from sklearn.externals import joblib
from pandas import DataFrame
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB
from optparse import OptionParser
from assimilate_utils import BroLogReader

if __name__ == "__main__":

    __version__ = '1.0'
    usage = """assimilate-assess [options] bro_http_header_file"""
    parser = OptionParser(usage=usage, version=__version__)
    parser.add_option("-f", "--headerfile", action="store", type="string", \
                      default=None, help="the Bro HTTP Header file to analyze")
    parser.add_option("-d", "--dirheaderfiles", action="store", type="string", \
                      default=None, help="directory of Bro HTTP Header files to analyze")
    parser.add_option("-b", "--bayesianfile", action="store", type="string", \
                      default='./nb.pkl', help="the location to load the bayesian classifier")
    parser.add_option("-x", "--vectorizerfile", action="store", type="string", \
                      default='./vectorizers.pkl', help="the location to load the vectorizer")
    parser.add_option("-o", "--outputfile", action="store", type="string", \
                      default=None, help="the file to store results in")
    parser.add_option("-v", "--verbose", action="store_true", default=False, \
                      help="enable verbose output")

    (opts, args) = parser.parse_args()
    
    if (opts.headerfile == None) & (opts.dirheaderfiles == None):
        parser.error('Need either a bro_http_header_file or a directory of bro_header_files to assess')

    blr = BroLogReader()
    data = DataFrame({'header': [], 'class': []})
    header_rows = []
    vectorizer = CountVectorizer()
    counts = vectorizer

    classifier = MultinomialNB()

    print('Loading models...')
    classifier = joblib.load(opts.bayesianfile)
    vectorizer = joblib.load(opts.vectorizerfile)
    
    if opts.headerfile != None:  
        print('Assessing HTTP Header file...')
        header_rows = blr.dataFrameFromFile(opts.headerfile)
    
        rowindex = 1
        if opts.outputfile != None:
            of = open(opts.outputfile, "w")
        for r1 in header_rows:
            if opts.verbose:
                print("Checking line "+str(rowindex))
            indhdr = [r1['header']]
            tstcounts = vectorizer.transform(indhdr)
            predictions = classifier.predict(tstcounts)
            if predictions[0] == 'bad':
                if len(r1['header']) > 60:
                    print("Line "+str(rowindex)+" looks suspicious: "+r1['header'][:60])
                else:
                    print("Line "+str(rowindex)+" looks suspicious: "+r1['header'])
                if opts.outputfile != None:
                    of.write("Line "+str(rowindex)+" looks suspicious: "+r1['header']+"\n")
            rowindex += 1
    
        if opts.outputfile != None:
            of.close()
        print('Done!')
    else:
        print('Assessing directory '+opts.dirheaderfiles+'...')
        header_rows = blr.AssessdataFrameFromDirectory(opts.dirheaderfiles)
    
        rowindex = 1
        fn = header_rows[0]['filename']
        if opts.outputfile != None:
            of = open(opts.outputfile, "w")
        for r1 in header_rows:
            if fn != r1['filename']:
                rowindex = 1
                fn = r1['filename']
            if opts.verbose:
                print("Checking file "+r1['filename']+" line "+str(rowindex)+" of file "+r1['filename'])
            indhdr = [r1['header']]
            tstcounts = vectorizer.transform(indhdr)
            predictions = classifier.predict(tstcounts)
            if predictions[0] == 'bad':
                if len(r1['header']) > 40:
                    print("File "+r1['filename']+" Line "+str(rowindex)+" looks suspicious: "+r1['header'][:40])
                else:
                    print("File "+r1['filename']+" Line "+str(rowindex)+" looks suspicious: "+r1['header'])
                if opts.outputfile != None:
                    of.write("File "+r1['filename']+" Line "+str(rowindex)+" looks suspicious: "+r1['header']+"\n")
            rowindex += 1
    
        if opts.outputfile != None:
            of.close()
        print('Done!')
        