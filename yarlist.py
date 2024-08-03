import glob, os


def filetext_to_yara_strings(file, char_to_remove='', fullword=True, nocase=False, xor=False):
    with open(file, 'r') as f:
        try:
            lines = f.readlines()
            yara_strings = ["        $ = \"{}\"{}{}{} wide ascii"
                        .format(line.strip().replace(char_to_remove, ''),
                        ('', " fullword")[fullword],
                        ('', " nocase")[nocase & ~xor],
                        ('', " xor")[xor & ~nocase])
                        for line in lines]
            return yara_strings
        except Exception as e:
            print("An error occurred reading `%s`: " % file, e)


def generate_yara_from_lists(filepath, prefix_word="", filename_word_to_remove="", char_to_remove='', ruleset_license='', any_cond=True):
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
            yara_rulename = '_' + yara_rulename[:127]
        yara_rulename_charmap = yara_rulename.maketrans("".join([' ', '.', '-']), "___")
        yara_rulename = yara_rulename.translate(yara_rulename_charmap)
        #yara_rulename = yara_rulename.replace("-", "_").replace(" ", '_')

        rule_license_field = ""
        if ruleset_license:
            rule_license_field = "\n        license = \"{}\"".format(ruleset_license)

        yara_rule = '''rule {} {{
    meta:{}
        source = "{}"
    strings:
{}
    condition:
        {} of them
}}
'''.format(yara_rulename, rule_license_field, filename, "\n".join(filetext_to_yara_strings(file, char_to_remove)), ("all", "any")[any_cond])
        #print(yara_rule)

        yara_ruleset += yara_rule

    return yara_ruleset
