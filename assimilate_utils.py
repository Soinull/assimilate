class BroLogReader():
    ''' This class implements a python based Bro Log Reader. '''

    def __init__(self):
        ''' Init for BroLogReader. '''
        self._delimiter = '\t'

    def read_log(self, logfile, max_rows=None):
        ''' The read_log method is a generator for rows in a Bro log. 
            Usage: rows = my_bro_reader.read_log(logfile) 
                   for row in rows:
                       do something with row
            Because this method returns a generator, it's memory
            efficient and does not read the entire file in at once.
        '''
        
        import csv, itertools

        # First parse the header of the bro log
        bro_fptr, field_names, field_types = self._parse_bro_header(logfile)
        
        # Note: The parse_bro_header method has advanced us to the first
        #       real data row, so we can use the normal csv reader.
        reader = csv.DictReader(bro_fptr, fieldnames=field_names,
                                delimiter=self._delimiter, restval='BRO_STOP')
        for _row in itertools.islice(reader, 0, max_rows):
            values = self._cast_dict(_row)
            if (values):
                yield values

    def _parse_bro_header(self, logfile):
        ''' This method tries to parse the Bro log header section.
            Note: My googling is failing me on the documentation on the format,
                  so just making a lot of assumptions and skipping some shit.
            Assumption 1: The delimeter is a tab.
            Assumption 2: Types are either time, string, int or float
            Assumption 3: The header is always ends with #fields and #types as
                          the last two lines.
            
            Format example:
                #separator \x09
                #set_separator	,
                #empty_field	(empty)
                #unset_field	-
                #path	httpheader_recon
                #fields	ts	origin	useragent	header_events_json
                #types	time	string	string	string
        '''

        # Open the logfile
        _file = open(logfile, 'rb')

        # Skip until you find the #fields line
        _line = next(_file)
        while (not _line.startswith('#fields')):
            _line = next(_file)

        # Read in the field names
        _field_names = _line.strip().split(self._delimiter)[1:]

        # Read in the types
        _line = next(_file)
        _field_types = _line.strip().split(self._delimiter)[1:]

        # Return the header info
        return _file, _field_names, _field_types

    def _cast_dict(self, data_dict):
        ''' Internal method that makes sure any dictionary elements
            are properly cast into the correct types, instead of
            just treating everything like a string from the csv file
        ''' 
        for key, value in data_dict.iteritems():
            if (value == 'BRO_STOP'):
                return None
            data_dict[key] = value
        return data_dict

    def readFiles(self, path):
        import os

        bro_log = BroLogReader()
        for root, dirnames, filenames in os.walk(path):
            for filename in filenames:
                path = os.path.join(root, filename)

                log_records = bro_log.read_log(path)

                yield path, log_records

    def readFile(self, filename):
        bro_log = BroLogReader()
        log_records = bro_log.read_log(filename)

        yield log_records


    def dataFrameFromDirectory(self, path, classification):
        rows = []
        for filename, log_records in self.readFiles(path):
            for r1 in log_records:
                rows.append({'header': r1['header_events_kv'], 'class': classification})

        return rows

    def AssessdataFrameFromDirectory(self, path):
        rows = []
        for filename, log_records in self.readFiles(path):
            for r1 in log_records:
                rows.append({'header': r1['header_events_kv'], 'filename': filename})

        return rows

    def dataFrameFromFile(self, filename):
        rows = []
        for log_records in self.readFile(filename):
            for r1 in log_records:
                rows.append({'header': r1['header_events_kv']})

        return rows
