import re
import regex

class Rule(dict):
    ''' breaks the rule into its parts along with validating it '''
    
    def __init__(self, rule):
        ''' self['valid'] will be changed at any point to show whether the rule is valid or not. Error will tell you where.'''
        self['valid'] = True
        self['error'] = None
        self['rawRule'] = rule
        
        self.header()
    
    def __getattr__(self, i):
        ''' Get any value from the dict '''
        return self[i]
    
    def header(self):
        ''' maps the header options to self'''
        
        if re.match(regex.rule_header, self['rawRule']):
            header = re.match(regex.rule_header, self['rawRule']).groupdict()
            for option in header:
                self[option] = header[option]
        else:
            self['valid'] = False
    
    def generalOptions(self):
        pass
    
    def payloadDetection(self):
        pass
    
    def nonpayloadDetection(self):
        pass
    
    def postDetection(self):
        pass

if __name__ == "__main__":
    
    myFile = open("rules/community.rules")
    
    i = 0
    rule = {}
    for line in myFile:
        rule[i] = Rule(line)
        print rule[i].valid
        i += 1