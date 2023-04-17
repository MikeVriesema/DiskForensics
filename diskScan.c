/*
 * diskScan.c
 * Module: ET4027 - Computer Forensics Tool
 * Summary: Disk Forensics Tool 
 * Used to analyse General Partition Information
 * FAT Volume Information
 * First deleted file in the root directory
 * NTFS & $MFT Information
 * 
 * Authors: Luke O'Sullivan Griffin - 17184614
 *	    	Mike Vriesema - 17212359
 * Date: 21/02/2021
 */

//IMPORTED LIBRARIES
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

//FUNCTION & STRUCT DECLARATIONS:
struct Partition{ 
	char type; 
	int sectorStart; 
	int size;
}partitionNumber[4];

struct FileData{
	char filedata[24];
	char deletedFileName[12];
	int startAddr[2];
	int fileSize[4];
}data;

void fetchPartitionType(char partitionType, char *volumeType);
void fetchPartitionInfo(char *fileName, int *sectorStartPos, int *partitionBlank, long long int *ntfsStart);
void fetchFatVolumeInfo(char *fileName, int *sectorStartPos);
void fetchDeletedFileInfo(char *fileName, int fileStartPos, int secondClusterAddr);
void fetchNTFSVolumeInfo(char *fileName, long long int *ntfsStart);
void fetchMFTAttribute(int attributeType, char *attribute);
void fetchMFTData(int attributeCount, FILE *mftInfo ,int mftAddr,int mftOffset);
void printIntroTable(void);
void printPartitionInfo(char *fileName, int *partitionBlank);
void readInput(char *fileName);
unsigned int bigToLittleEndian(unsigned int binary);
int readChoice();

/*
 * Main: 
 * --------------------
 * Runs default menu
 * Requests file name and tests to see if it exists and can be opened
 * Re-requests file name on failure before launching core menu loop
 * Calls other functions depending on user inputted choice
 * 
 * Parameters: argc, char *argv[] Possible commandline arguments, passed as int or char values
 * int: Default C return value determining exit status
 */
int main(int argc, char *argv[]){
    char fileName[128]; //DECLARES CHAR ARRAY TO STORE DISK IMAGE FILE NAME
	int choice; //DECLARES INT CHOICE VARIABLES USED IN MENU NAVIGATION
	int sectorStartPos = 0, partitionBlank = 0; //1ST PARTITION SECTOR START, NUM OF BLANK PARTITIONS
	long long int ntfsStart = 0;

	FILE *fileTest; //TESTING TO SEE IF DISK IMAGE FILE CAN BE ACCESSED
	printIntroTable();
    do{ //MAIN MENU LOOP
		printf("Enter disk file name to be tested: ");
		readInput(fileName); //READS USER INPUT FOR DISK IMAGE NAME
		fileTest = fopen(fileName, "rb"); //OPEN FILE FOR READING -> rb INDICATES BINARY MODE
		if(fileTest != NULL){ //ERROR CHECK FOR FILE NAME EXISTING
			do{
				printf("\nPress 1 to view General Partition Information\n"); //PHASE 1 (PARTITION INFO)
				printf("Press 2 to view FAT Volume Information\n"); //PHASE 2 (FAT VOLUME INFO)
				printf("Press 3 to view NTFS Volume Information\n"); //PHASE 2 (NTFS VOLUME INFO)
				printf("Press 4 to exit the program\n"); //EXIT PROGRAM OPTION
				printf("Enter your choice: "); 
				choice = readChoice(); //CALLS READ INPUT METHOD
				printf("\n");
				fetchPartitionInfo((char*)fileName, &sectorStartPos, &partitionBlank, &ntfsStart);
				switch (choice){  
					case 1: { //PHASE 1 (PARTITION INFO)
						printf("\e[1;1H\e[2J");
						printPartitionInfo((char*)fileName, &partitionBlank);
						break;
					} 
					case 2: { //PHASE 2 (FAT VOLUME INFO)
						printf("\e[1;1H\e[2J");
						fetchFatVolumeInfo((char*)fileName, &sectorStartPos);
						break;
					} 
					case 3: { //PHASE 2 (NTFS VOLUME INFO)
						printf("\e[1;1H\e[2J");
						fetchNTFSVolumeInfo((char*)fileName, &ntfsStart);
						break;
					} 
					case 4: { //EXIT BRANCH
						printf("Exiting Program\n");
						choice = 0;
						break;
					}
					default: //DEFAULT TO AVOID INCORRECT INPUT WILL EXIT PROGRAM
						printf("No valid input detected\nExiting program\n"); 
						choice = 0;
						break;
				} 
			}while(choice != 0);
		}else{
			perror("Failed ");
			choice = 5;
		}		
    }while(choice != 0);
}


/*
 * Function:  fetchPartitionInfo 
 * --------------------
 * Reads in the binary data of the disk file and seeks the start of the MBR
 * Reads the next 64 Bytes of data into a char buffer
 * Cycles through the 4 possible partitions and increments the blank partition value if needed
 * It retrieves the partition number, start sector, and size.
 * It also does a function call to iterate the type through a switch to fetch the partition type
 * It then prints the partition details to the console
 * 
 * fileName: The fileName of the disk to assess Partition Info
 * sectorStartPos: The start address of the FAT Volume
 * partitionBlank: The number of inactive partitions
 * ntfsStart: The start address of the NTFS Boot Sector
 */
void fetchPartitionInfo(char *fileName, int *sectorStartPos, int *partitionBlank, long long int *ntfsStart){
	//DATA DECLARATION
    int i, byteOffset = 16; 
	int invalidPartition = 0;
	char partitionDataBuffer[64];
	char volumeType[16];
    FILE *partitionInfo;
    //DATA MANIPULATION			
    partitionInfo = fopen(fileName, "rb"); //OPEN FILE FOR READING -> rb INDICATES BINARY MODE
	fseek(partitionInfo, 0x1BE, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF PARTITION TABLE AT 0x1BE)  
	fread(partitionDataBuffer, 1, 64, partitionInfo); //READS IN FIRST 64 BYTES OF DATA TO THE DATA BUFFER	
	for(i=0;i<4;i++){ //CYCLE FOR THE 4 PRIMARY PARTITIONS, CANNOT HAVE MORE THAN 4 WITHOUT A DYNAMIC DISK AND STANDARD MBR
		partitionNumber[i].type = *(char*)(partitionDataBuffer + 0x04 +(i * byteOffset)); //USING THE OFFSET OF 16 CYCLES ACROSS THE PARTITION DATA FROM 0x1BE (START OF PARTITION TABLE ENTRY)
		if(partitionNumber[i].type==0)invalidPartition++; //IF THE TYPE IDENTIFIER IS 0x00 IT IS AN UNKNOWN OR EMPTY PARTITION
		partitionNumber[i].sectorStart = *(int*)(partitionDataBuffer+0x08+(i*byteOffset)); //READS THE START SECTOR VALUE (LB ADDRESS)
		partitionNumber[i].size = *(int*)(partitionDataBuffer+0x0C+(i*byteOffset)); //READS THE PARTITION SIZE VALUE (NUM OF SECTORS)
		partitionNumber[i].size = (partitionNumber[i].size *512)/1024; //CONVERSION OF SECTOR COUNT * 512 BYTES/1024 TO GET PARTITION SIZE IN KiB
		fetchPartitionType(partitionNumber[i].type,(char*)volumeType);
		if(partitionNumber[i].type == 06){ //SETS FAT VOLUME START SECTOR
			*sectorStartPos = *(int*)(partitionDataBuffer+0x08+(i*byteOffset));
		}
		if(partitionNumber[i].type == 07){//SETS NTFS VOLUME START SECTOR
			*ntfsStart = *(int*)(partitionDataBuffer+0x08+(i*byteOffset)); 
		}
	}
	*partitionBlank = invalidPartition;
	fclose(partitionInfo); // CLOSE OPEN FILE
}


/*
 * Function:  printPartitionInfo 
 * --------------------
 * Prints partition information stored in pointers and in
 * the partition structs set via the function call before the menu is loaded
 * 
 * partitionBlank: Number of inactive partitions
 */
void printPartitionInfo(char *fileName, int *partitionBlank){
	int i;
	char type[16];
	printf("%-15s%-s%-s\n","\n","PARTITION TABLE DATA: ",(char*)fileName);
	printf("|----------------------------------------------------------|\n");
	printf("| Partition:  | Type:        | Start Sector: | Size (KiB): |\n");
	printf("|----------------------------------------------------------|\n");
	for(i=0;i<4;i++){ //PRINT OUT PARTITION INFORMATION
		fetchPartitionType(partitionNumber[i].type,(char*)type);
		printf("| Partition %-4d%-15s%-16d%-12d%-1s\n", i, type, partitionNumber[i].sectorStart, partitionNumber[i].size,"|");
		printf("|----------------------------------------------------------|\n");
	}
	printf("%-9s%-s%d\n\n","\n","The total number of active partitions is: ", (4 - *partitionBlank));
}


/*
 * Function:  fetchPartitionType 
 * --------------------
 * Uses a switch statement to determine partition type based on bytecode
 *	
 *	Key Code Descriptions for Partition Types:
 *	00h : Unknown or empty
 *	01h : 12-bit FAT
 *	04h : 16-bit FAT (< 32MB)
 *	05h : Extended MS-DOS Partition
 *	06h : FAT-16 (32MB to 2GB)
 *	07h : NTFS
 *	0Bh : FAT-32 (CHS)
 *	0Ch : FAT-32 (LBA)
 *	0Eh : FAT-16 (LBA)
 *
 *  partitionType: The bytecode of the partition type
 * 	volumeType: Pointer to the char array that stores the string of the
 *  partition type
 */
void fetchPartitionType(char partitionType, char *volumeType){
	switch(partitionType){ //SWITCHES THROUGH THE MAIN POSSIBLE TYPES A PARTITION CAN BE
		case 00 : strcpy(volumeType, "UNKNOWN/EMPTY"); 
		break;  
		case 01 : strcpy(volumeType, "12-BIT FAT"); 
		break;
		case 04 : strcpy(volumeType, "16-BIT FAT"); 
		break;
		case 05 : strcpy(volumeType, "EXT. MS-DOS"); 
		break;
		case 06 : strcpy(volumeType, "FAT-16"); 
		break;
		case 07 : strcpy(volumeType, "NTFS"); 
		break;
		case 0x0B: strcpy(volumeType, "FAT-32(CHS)"); 
		break;
		case 0x0C: strcpy(volumeType, "FAT-32(LBA)"); 
		break;
		case 0x0E: strcpy(volumeType, "FAT-16(LBA)"); 
		break;
		default: strcpy(volumeType, "NOT-RECOGNISED"); 
		break;
	}
}


/*
 * Function:  fetchFatVolumeInfo 
 * --------------------
 * Retrieves FAT Volume Information such as
 * Sectors per Cluster, FAT Area Size, Root Directory Size, and
 * the Sector address of #2 Cluster.
 * It also calls the function to retrieve remaining details about
 * the first deleted file in the root directory.
 * It then prints the FAT Volume details to the console
 * 
 * fileName: The fileName of the disk to assess FAT Volume Info
 * sectorStartPos: The start address of the FAT Volume
 */
void fetchFatVolumeInfo(char *fileName,int *sectorStartPos){
	//DATA DECLARATION
	int sectorsPerCluster, reserved;
	int maxRootDir, rootDirSize;
	int fatCopy, fatSize;
	int secondClusterAddr, dataSectorAddr;
	unsigned char sizeOfFat;
	unsigned char volumeDataBuffer[64];
    FILE *volumeInfo;
    //DATA MANIPULATION			
    volumeInfo = fopen(fileName, "rb"); //OPEN FILE FOR READING -> rb INDICATES BINARY MODE
	fseek(volumeInfo, *sectorStartPos*512, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF VOLUME INFO TABLE)
	fread(volumeDataBuffer, 1, 64, volumeInfo); //READS IN FIRST 64 BYTES OF DATA TO THE DATA BUFFER
	reserved = *(char*)(volumeDataBuffer+0x0E); //RESERVED AREA SIZE IN BYTES
	sectorsPerCluster = *(char*)(volumeDataBuffer+0x0D);
	fatCopy = *(char*)(volumeDataBuffer+0x10); //NUMBER OF COPIES OF FAT
	sizeOfFat = *(char*)(volumeDataBuffer+0x16); //SIZE OF EACH FAT IN SECTORS
	fatSize = sizeOfFat*fatCopy; //FAT TOTAL SIZE = (SIZE OF EACH FAT IN SECTORS)*(NUMBER OF COPIES OF FAT)
	maxRootDir = bigToLittleEndian((unsigned int)(*(char*)(volumeDataBuffer+0x12))); //MAXIMUM NUMBER OF ROOT DIRECTORIES
	rootDirSize = (maxRootDir*32)/512;//ROOT DIR SIZE = ( MAX. NUM. OF DIR ENTRIES)*(DIR ENTRY SIZE IN BYTES)/SECTOR SIZE
	//NOTE: DIRECTORY ENTRY SIZE FOR FAT VOLUME IS ALWAYS 32 BYTES
	dataSectorAddr = *sectorStartPos + reserved + fatSize;//(FIRST SECTOR OF VOLUME) + (SIZE OF RESERVED) + (FAT AREA SIZE);
	secondClusterAddr = dataSectorAddr + rootDirSize; //FIRST SECTOR OF VOLUME + THE ROOT DIRECTORY TOTAL SIZE
	fclose(volumeInfo); //CLOSES OPEN FILE
	printf("%-36s%-s\n","\n","FAT Volume Information");
	printf("|----------------------------------------------------------------------------------------------|\n");
	printf("| Sectors per Cluster: | FAT Area Size: | Root Directory Size: | Sector Address of Cluster #2: |\n");
	printf("|----------------------------------------------------------------------------------------------|\n");
	printf("| %-23d%-17d%-23d%-30d|\n",sectorsPerCluster,fatSize,rootDirSize,secondClusterAddr);
	printf("|----------------------------------------------------------------------------------------------|\n");
	fetchDeletedFileInfo((char*)fileName, dataSectorAddr, secondClusterAddr);
}


/*
 * Function:  fetchDeletedFileInfo 
 * --------------------
 * Retrieves deleted file information such as the file name,
 * file size in kilobytes, the file Cluster Sector address,
 * and the first 16 characters of the deleted file.
 * It then prints the deleted file information to the console
 * 
 * fileName: The fileName of the disk to assess FAT Volume Info
 * fileStartPos: The start address of the deleted file
 * secondClusterAddr: The address of the #2 Cluster
 */
void fetchDeletedFileInfo(char *fileName, int fileStartPos, int secondClusterAddr){
	//DATA DECLARATION
	int firstByte, nameByte, i=0, j=0;
	char fileNameInfo[] = "NOTE: Long File name entry";
	unsigned char directoryDataBuffer[32];
	FILE *directoryInfo;
    //DATA MANIPULATION			
	fileStartPos = (fileStartPos*512);
    directoryInfo = fopen(fileName, "rb"); //OPEN FILE FOR READING -> rb INDICATES BINARY MODE
	do{
		//START ROOT DIR (SECTOR 567) -> END OF ROOT DIR AT CLUSTER #2 (SECTOR 599)
		fseek(directoryInfo, fileStartPos, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF ROOT DIRECTORY)
		fread(directoryDataBuffer, 1, 32, directoryInfo); //READS IN FIRST 32 BYTES OF DATA TO THE DATA BUFFER
		for(i=0;i<32;i++){
			nameByte = *(char*)(directoryDataBuffer+0x0B); //NAMEBYTE FOR CHECKING IF FILE NAME IS EXTRA LONG
			if(i<11){
				data.deletedFileName[i] = *(char*)(directoryDataBuffer+0x00+i); //FILE NAME (FIRST 11 BYTES)
			}
		}
		firstByte = directoryDataBuffer[0]; //FIRST BYTE TO CHECK IF FILE IS DELETED
		fileStartPos = fileStartPos+32; //MOVE FILE START POSITION FORWARD 32 BYTES TO NEXT FILE ENTRY
		if(firstByte == 0xE5){ //IF THE FIRST BYTE MATCHES 0xE5 (229) IT IS A DELETED FILE
			strcpy((char*)data.startAddr, (char*)(directoryDataBuffer+0x1B)); //STARTING CLUSTER ADDRESS (0x1B)(0 IF EMPTY)
			strcpy((char*)data.startAddr, (char*)(directoryDataBuffer+0x1A)); //STARTING CLUSTER ADDRESS (0x1A)(0 IF EMPTY) CLUSTER SECTOR ADDRESS = #2 CLUSTER ADDR + ((DATA ADDR-2)*8)
			strcpy((char*)data.fileSize, (char*)(directoryDataBuffer+0x1F)); //FILE SIZE (0x1F)31
			strcpy((char*)data.fileSize, (char*)(directoryDataBuffer+0x1E)); //FILE SIZE (0x1E)30
			strcpy((char*)data.fileSize, (char*)(directoryDataBuffer+0x1D)); //FILE SIZE (0x1D)29
			strcpy((char*)data.fileSize, (char*)(directoryDataBuffer+0x1C)); //FILE SIZE (0x1C)28	
			fseek(directoryInfo,((secondClusterAddr+((*data.startAddr-2)*8))*512), SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF FIRST CLUSTER OF FILE)
			fread(directoryDataBuffer, 1, 32, directoryInfo); //READS IN FIRST 64 BYTES OF DATA TO THE DATA BUFFER
			fclose(directoryInfo); //CLOSES OPEN FILE
			for(j=0;j<16;j++){
				data.filedata[j] = *(char*)(directoryDataBuffer+0x04+j); //FILE CHARACTERS(FIRST 16)
			}
			printf("%-24s%s\n","\n\n","First Deleted File found on Root Directory:");
			printf("|----------------------------------------------------------------------------------------|\n");
			printf("| Name:        | File Size (KiB): | File Cluster Sector Address: | First 16 Characters:  |\n");
			printf("|----------------------------------------------------------------------------------------|\n");
			printf("| %-15s%-19.2f%-31d%s%-s%-5s%-s",(char*)data.deletedFileName,(float)*data.fileSize/1024,(((*data.startAddr-2)*8)+secondClusterAddr),"\"",(char*)data.filedata,"\"","|\n");
			printf("|----------------------------------------------------------------------------------------|\n");
			if(nameByte == 0x0F){
				printf("%-26s%s\n","\n",fileNameInfo);
			}
			break;
		}
	}while(fileStartPos < secondClusterAddr*512); //STOP DO LOOP IF A DELETED FILE IS DETECTED OR THE END OF THE ROOT DIRECTORY IS REACHED	
}


/*
 * Function:  fetchNTFSVolumeInfo 
 * --------------------
 * Fetches relevant NTFS Boot Sector details such as the
 * bytes per Sector, sectors per Cluster, and $MFTOffset
 * It then prints these NTFS Volume details to the console
 * It also calls the function to retrieve remaining $MFT details
 * 
 * fileName: The fileName of the disk to assess NTFS Volume Info
 * ntfsStart: The start address for the NTFS Boot Sector
 */
void fetchNTFSVolumeInfo(char *fileName, long long int *ntfsStart){
	//DATA DECLARATION
	int bytesPerSector, sectorsPerCluster;
	long long int mftSectorAddr;
	int mftAttrOffset[2]; 
	unsigned char ntfsDataBuffer[64];
    FILE *ntfsInfo;
    //DATA MANIPULATION			
    ntfsInfo = fopen(fileName, "rb"); //OPEN FILE FOR READING -> rb INDICATES BINARY MODE
	fseek(ntfsInfo, *ntfsStart*512, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF NTFS BOOT SECTOR) 
	fread(ntfsDataBuffer, 1, 64, ntfsInfo); //READS IN FIRST 64 BYTES OF DATA TO THE DATA BUFFER
	bytesPerSector = bigToLittleEndian((unsigned int)(*(char*)(ntfsDataBuffer+0x0C))); //BYTES PER SECTOR FOR NTFS VOLUME (0x0B -> 0x0C)
	sectorsPerCluster = *(char*)(ntfsDataBuffer+0x0D); //SECTORS PER CLUSTER IN NTFS VOLUME
	mftSectorAddr = *(char*)(ntfsDataBuffer+0x30); //LOGICAL CLUSTER NUMBER FOR MASTER FILE TABLE
	mftSectorAddr = *ntfsStart+(mftSectorAddr*sectorsPerCluster); //MFT SECTOR ADDRESS = NTFS TABLE ADDRESS + (LOGICAL CLUSTER NUMBER * SECTORS PER CLUSTER)
	printf("%-22s%-s%-s","\n","NTFS Volume Information","\n");
	printf("|----------------------------------------------------------------|\n");
	printf("| Bytes per Sector: | Sectors per Cluster: | $MFT Sector Address |\n");
	printf("|----------------------------------------------------------------|\n");
	printf("| %-21d%-22d%-20lld|\n",bytesPerSector,sectorsPerCluster, mftSectorAddr);
	printf("|----------------------------------------------------------------|\n");
	fseek(ntfsInfo,mftSectorAddr*512, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF $MFT TABLE) 
	fread(ntfsDataBuffer, 1, 32, ntfsInfo); //READS IN FIRST 32 BYTES OF DATA TO THE DATA BUFFER
	mftAttrOffset[0] = *(char*)(ntfsDataBuffer+0x14); //$MFT ATTRIBUTE OFFSET
	fetchMFTData(2,ntfsInfo,mftSectorAddr*512,*mftAttrOffset);
	fclose(ntfsInfo); //CLOSES OPEN FILE
}


/*
 * Function:  fetchMFTData 
 * --------------------
 * Function navigates to $MFT sector and 
 * retrieves various $MFT attributes such as length and type.
 * Loops for the attributeCount duration.
 * It then prints the NTFS Volume details to the console.
 * 
 * attributeCount: The number of attributes data should be acquired for
 * mftInfo: The file with $MFT Data in it
 * mftAddr: The start address in bytes for the $MFT Sector
 * mftOffset: The offset of the $MFT attributes in the MFT Sector
 */
void fetchMFTData(int attributeCount, FILE *mftInfo ,int mftAddr,int mftOffset){
	//DATA DECLARATION
	char mftAttribute[21];
	int mftLength[3];
	int mftAttrLength = 0;
	int mtfType = 0;
	unsigned char mftDataBuffer[64];
	//DATA MANIPULATION
	printf("%-16s%s\n","\n\n","$MFT Attribute Information");
	printf("|-----------------------------------------------------|\n");
	printf("| $MFT Attribute: | $MFT Attribute Type:   |  Length: |\n");
	printf("|-----------------------------------------------------|\n");
	for(int h = 0;h<attributeCount;h++){ //LOOPS FOR THE VALUE OF THE PARAMETER
		fseek(mftInfo,(mftAddr)+mftOffset+mftAttrLength, SEEK_SET); //GOES TO START (SEEK_SET FLAG) OF FILE (IN THIS CASE ADDRESS OF ATTRIBUTE) 
		fread(mftDataBuffer, 1, 64, mftInfo); //READS IN FIRST 64 BYTES OF DATA TO THE DATA BUFFER
		mtfType = *(char*)(mftDataBuffer+0x00); //MFT ATTRIBUTE TYPE
		mftLength[0] = *(char*)(mftDataBuffer+0x04); //MFT ATTRIBUTE LENGTH
		mftAttrLength = mftAttrLength + *mftLength; //CONTINUOUSLY ADDS THE PREVIOUS ATTRIBUTE LENGTH TO ALLOW MORE ATTRIBUTES TO BE SEARCHED
		fetchMFTAttribute(mtfType, (char*)mftAttribute); //RETRIEVES ATTRIBUTE TYPE FROM BYTECODE
		printf("| %s%-7d%-26s%-8d|\n","Attribute #",h+1,mftAttribute,*mftLength);
		printf("|-----------------------------------------------------|\n");
	}
}

/*
 * Function:  fetchMFTAttribute 
 * --------------------
 * Uses a switch statement to determine attribute type based on bytecode
 *	
 *	Key Code Descriptions for Partition Types:
 *	0x10 : STANDARD_INFORMATION
 *	0x20 : ATTRIBUTE_LIST
 *	0x30 : FILE_NAME
 *	0x40 : OBJECT_ID
 *	0x60 : VOLUME_NAME
 *	0x70 : VOLUME_INFORMATION
 *	0x80 : DATA
 *	0x90 : INDEX_ROOT
 *	0xA0 : INDEX_ALLOCATION
 *	0xB0 : BITMAP
 *	0xC0 : REPARSE_POINT
 *
 *  attributeType: The bytecode of the attribute type
 * 	attribute: Pointer to the char array that stores the string of the
 *  attribute type
 * 	Source: https://docs.microsoft.com/en-us/windows/win32/devnotes/attribute-list-entry
 */
void fetchMFTAttribute(int attributeType, char *attribute){
	switch(attributeType){ //SWITCHES THROUGH THE MAIN POSSIBLE TYPES A PARTITION CAN BE
		case 0x10 : strcpy(attribute, "$STANDARD_INFORMATION"); 
		break;  
		case 0x20 : strcpy(attribute, "$ATTRIBUTE_LIST"); 
		break;
		case 0x30 : strcpy(attribute, "$FILE_NAME"); 
		break;
		case 0x40 : strcpy(attribute, "$OBJECT_ID"); 
		break;
		case 0x60 : strcpy(attribute, "$VOLUME_NAME"); 
		break;
		case 0x70 : strcpy(attribute, "$VOLUME_INFORMATION"); 
		break;
		case 0x80: strcpy(attribute, "$DATA"); 
		break;
		case 0x90: strcpy(attribute, "$INDEX_ROOT"); 
		break;
		case 0xA0: strcpy(attribute, "$INDEX_ALLOCATION"); 
		break;
		case 0xB0: strcpy(attribute, "$BITMAP"); 
		break;
		case 0xC0: strcpy(attribute, "$REPARSE_POINT"); 
		break;
		default: strcpy(attribute, "NOT-RECOGNISED"); 
		break;
	}
}


/*
 * Function:  printIntroTable 
 * --------------------
 * Prints a pretty little table with module & author information
 */
void printIntroTable(){
	printf("\n\n");
	printf("|------------------------------------------------------|\n");
	printf("|          ET4027 - Computer Forensics Tool            |\n");
	printf("|       By Luke O'Sullivan Griffin - 17184614          |\n");
	printf("|             & Mike Vriesema - 17212359               |\n");
	printf("|------------------------------------------------------|\n\n");
	printf("\nMAIN MENU:\n\n");
}


/*
 * Function:  readChoice 
 * --------------------
 * Reads user input expecting an int
 * Used for making menu choices
 * 
 * Return: int - value(user inputted value)
 */
int readChoice(){
   int value;
   scanf("%d",&value);
   return value;
}


/*
 * Function:  readInput 
 * --------------------
 * Reads user input expecting a string
 * Is assigned to fileName char pointer 
 * (stores fileName of disk)
 * 
 * fileName: Pointer of filename
 */
void readInput(char *fileName){
	scanf("%s",fileName);
}


/*
 * Function:  bigToLittleEndian 
 * --------------------
 * Converts passed in value from 
 * little endian to big endian
 * 
 * val: Value to be converted
 * unsigned int: Returns converted value
 */
unsigned int bigToLittleEndian(unsigned int binary ){
	return (binary>>8)|(binary<<8); //BYTE SWAP UNSIGNED SHORT INT
}
