import glob, os, sys


def generate_yara_from_lists(filepath, prefix_word="", filename_word_to_remove="", char_to_remove=''):
    yara_ruleset = ""
    
    files = glob.glob(filepath + "{0}*".format(os.sep))
    #print(files)
    
    for file in files:
        # rsplit to handle possibility of filename with multiple '.' chars
        filename = file.split(os.sep)[-1].rsplit('.', 1)[0]
        
        if filename_word_to_remove:
            filename = filename.replace(filename_word_to_remove, "")
        #print(filename)
        
        yara_rulename = (prefix_word + filename)[:128]
        # validate yara rulename, replace invalid chars
        if yara_rulename[0].isdigit():
            yara_rulename = '_' + yara_rulename
        yara_rulename_charmap = yara_rulename.maketrans("".join([' ', '.', '-']), "___")
        yara_rulename = yara_rulename.translate(yara_rulename_charmap)
        #yara_rulename = yara_rulename.replace("-", "_").replace(" ", '_')
        
        with open(file, 'r') as f:
            lines = f.readlines()
        yara_strings = ["        $ = \"{}\" fullword wide ascii".format(line.strip().replace(char_to_remove, '')) for line in lines]
        #print(yara_strings)
        
        yara_rule = '''rule {0} {{
    meta:
        source = "{1}"
    strings:
{2}
    condition:
        any of them
}}

'''.format(yara_rulename, filename, "\n".join(yara_strings))
        #print(yara_rule)
        
        yara_ruleset += yara_rule
        
    return yara_ruleset
