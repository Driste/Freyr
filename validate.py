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
            self['error'] = "header"
    
    def generalOptions(self):
        pass
    
    def payloadDetection(self):
        pass
    
    def nonpayloadDetection(self):
        pass
    
    def postDetection(self):
        pass
    
    def checkOptions(self):
        ''' Make sure all the options are valid '''
        
        pass
    
    def checkGutters(self):
        ''' Check between all the options to make sure there is nothing unknown '''
        pass

if __name__ == "__main__":
    
    myFile = open("rules/community.rules")
    
    rule = 'alert tcp 192.168.100.40 $HOME_NET -> $H9 !45:56 (content:"|00 01 86 a5|"; msg:"This is the test rule.";)'
    
    print Rule(rule)
    
    '''
    i = 0
    rule = {}
    for line in myFile:
        rule[i] = Rule(line)
        print rule[i].srcport
        i += 1
    '''