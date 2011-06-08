
2to3:
	~/stuff/python/python/Python-3.2/python.exe ~/stuff/python/python/Python-3.2/Tools/scripts/2to3 python-lib >3.diff
	patch -p0 <3.diff
else:
	~/stuff/python/python/Python-3.2/python.exe ~/stuff/python/python/Python-3.2/Tools/scripts/2to3 bin/cfx
test:
	~/stuff/python/python/Python-3.2/python.exe bin/cfx testcfx
