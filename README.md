# DiskForensicsTool
## A COMPUTER "FORENSCIS" TOOOOOL  
### Report: [Overleaf](https://www.overleaf.com/project/602c0625145db87e4f3641b4)
---
## Usage
Prerequisites:  
To run the C code you must have "gcc" installed.  
To run the make file you must also have "make" installed.  
These can be installed with the following command on linux:  
```bash
sudo apt-get install build-essential
```
To compile and run the program, a makefile is provided.  
Ensure that the disk image file to be tested is in the same directory as the program and makefile.
The program can be run with the following command on linux: 
```bash
make
```
You will then be prompted to enter the name of the disk image file.
### Requirements (Phase 1):  
1. Display the number of partitions on the disk and for each partition display:  
    * The start sector.
    * Size of partition
    * File system type.  
2. Test the tool using the Sample1.dd image file to confirm that you can read the correct information.
3. Make  a  new  image  of  some  USB  disk  key  and  re-test  your  program  against your new disk image file and confirm the results.  
*As  part  of  testing  provide  evidence  that  you  have  mounted  the  image  as  away of confirming what information is contained on the image drive*  

#### Testing & Results:  
State how you tested your program or programs and record any results.    
This applies to both phases.  
Specifically include the following:  
1. Describe how you tested your program using the given image file  
2. Describe how you tested your program using your own image file, including evidence of mounting the image as described in Phase 1 Deliverables.  
3. Use screen shots as evidence of output for (i) and (ii) above.  
---
### Requirements (Phase 2):  
1. ##### Phase 2(A) – FAT Volume information – For the first partition only.  
    * Display the number of sectors per cluster1  
    * The size of the FAT area, the size of the Root Directory  
    * The sector address of Cluster 2.  
2. ##### For  the  first  deleted  file  on  the  volume’s  root  directory:  
    * Display the name and size of that file  
    * The number of the first cluster.  
    * Display the first 16 characters of the content of that file (assume it is a simple text file).  
1. ##### Phase 2(B): NTFS Volume information – Display information for an NTFS partition as follows:  
    * How many byes per sector for this NTFS volume  
    * How many sectors per cluster for this NTFS volume  
    * What is the sector address for the $MFT file record  
    * What is the type and length of the first two attributes in the $MFT record 
