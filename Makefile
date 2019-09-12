
help : 
	@echo
	@echo "make doc|clean"
	@echo
	

doc : *.php lib/*.php lib/BOC/*.php
	phpdoc --defaultpackagename=helpers --force

clean :	
	rm -rf phpdoc.cache

