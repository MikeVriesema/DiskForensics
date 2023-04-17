#########################################################
# Computer Forensics - Disk Analysis Tool
# makefile
# 
# Makefile that compiles targets for the disktool project
# And executes the final file and runs the clean target
# Use of @ suppresses the make commands outputting to console
# 
# Authors: 	Luke O'Sullivan Griffin 17184614 
# 			Mike Vriesema 17212359 	
# 
# Date Last Modified: 19/02/2021
#########################################################

# Lists targets to be executed in the makefile
exec := diskscan.o project clean

# Sets variables for use in makefile
main := diskScan

all: $(exec)

# Compile the main application .c file into .o 
diskscan.o: $(main).c
	@gcc -c $(main).c

# Compiles the final project using the 2 other object files and runs the application
	@gcc -o project $(main).o
	@./project

# Sets a clean target when finished by removing all .o files and the final project file
clean:
	@rm -f *.o project
