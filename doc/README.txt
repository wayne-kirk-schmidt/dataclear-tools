#
#==============================================================================
#
# harden-ubuntu [ options ] a script to harden Ubuntu Operating System
#
#	-h | --help		display this message and exit
#	-v | --verbose		run script verbosely for debugging 
#	-c | --checksum 	checksum the script, display it, and exit
#
# The script is currently run from: /tmp/sample/var
# The script install files into the following:
#
#	+ /var/tmp/hardening/cfg -- configuration files for exceptions
#	+ /var/tmp/hardening/var -- log files and output of specific runs
#	+ /var/tmp/hardening/bin -- this script and helper functions and code
#
#==============================================================================
#	
#	This script is designed to take an given ubuntu workstation or client
#	and turn this into a hardened host. This is by no means complete, 
#	and will be expanded on to reflect best practices. 
#	
#	Instead of having a complex script for mulitple OS, the design is 
#	build a script for each OS type, and then use a wrapper to 'choose' 
#	the right code to harden a machine.
#	
#	The goal is to build a single purpose appliance.
#	
#
#==============================================================================
#	
