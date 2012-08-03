## BlackLight/OpenPGP/Test/makefile
## Copyright 2012 Peter Franusic
##
## This file contains make commands to perform gpg operations
## for the hypothetical users "Genny" and "Blake".
## The commands are organized in a sort of chronological order:
## keys are generated, keys are listed, keys are exported,
## keys are imported, keys are signed, and finally, 
## keys can be used to transmit and receive OpenPGP messages.
## Most of this works non-interactively using the experimental "batch" mode.
## Genny's keyrings are kept in the BlackLight/OpenPGP/Test directory
## rather than the default ~/.gnupg directory.
## This makefile references two other files:
## Genny.keydef is referenced by the gen-key command.
## gpg.conf is referenced by the list, export, and import commands.
## 
## References:
## [1] Werner Koch, "Using the GNU Privacy Guard", 2009.
## [2] Free Software Foundation, "The GNU Privacy Handbook", 1999.
##


##
## Generate a set of keys for Genny.
## This command creates the keyring files Genny.secring and Genny.pubring.
## So, don't "make Genny-keys" unless you want to replace these two files.
##

Genny-keys:		Genny.keydef
			gpg --batch --gen-key Genny.keydef


##
## List the contents of Genny's secret and public keyrings.
##

Genny-list:		Genny.secring Genny.pubring
			gpg --options gpg.conf --list-secret-keys
			gpg --options gpg.conf --list-keys


##
## Export Genny's public keys from her public keyring.
##

Genny-export:		Genny.pubring
			gpg --options gpg.conf --output Genny.pgp --export Genny

##
## Import Blake's public keys into Genny's public keyring.
##

Blake-import:		Genny.pubring Blake.pgp
			gpg --options gpg.conf --import Blake.pgp


##
## Interactive commands for Genny to sign her copy of Blake's imported public keys.
## gpg requires Genny's signature in order to encrypt and verify using Blake's keys.
## Unfortunately, gpg does not have a facility to sign keys in batch mode.
## So we bite the bullet and wade through the interactive edit-key procedure.
## Therefore, enter "make Genny-signature" and answer the questions as shown below.
##

Genny-signature:	Genny.secring Genny.pubring
			gpg --no-default-keyring --secret-keyring ./Genny.secring --keyring ./Genny.pubring --edit-key Blake

##
## Questions and answers:
##
##   Command> sign
##
##   Really sign? (y/N) y
##
##   Enter passphrase: gentian
##
##   Command> trust
##
##   Your decision? 5
##
##   Do you really want to set this key to ultimate trust? (y/N) y
##
##   Command> save
##


