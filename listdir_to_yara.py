import sys

from yarlist import generate_yara_from_lists

if len(sys.argv) > 1:
	#print(sys.argv[1])
	print(generate_yara_from_lists(sys.argv[1]))
else:
	print("Usage: %s list_dir" % sys.argv[0])
