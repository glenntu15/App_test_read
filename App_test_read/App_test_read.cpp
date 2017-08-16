// App_test_read.cpp : Defines the entry point for the console application.
#include <string>
#include <stdio.h>
#include <tchar.h>
#include "sgx_urts.h"
#include "sgx_tseal.h"

#define ENCLAVE_FILE _T("Enclave_test_new.signed.dll")
//#define ENCLAVE_FILE _T("Enclave_test_save.signed.dll")
#define MAX_BUF_LEN 100

#include "sgx_urts.h"
#include "enclave_test_new_u.h"


int main()
{
	sgx_enclave_id_t   eid;
	sgx_status_t       ret = SGX_SUCCESS;
	sgx_launch_token_t token = { 0 };
	int updated = 0;
	char buffer[MAX_BUF_LEN] = "Hello World!";
	char secret[MAX_BUF_LEN] = "My secret string";
	char retSecret[MAX_BUF_LEN] = "";
	int secretIntValue = 0;
	int *secretIntPointer = &secretIntValue;
	int isdebug = SGX_DEBUG_FLAG;
	sgx_status_t status;
	sgx_status_t ecall_status;
	printf("\nApp debug = %d\n", isdebug);

	status = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &updated, &eid, NULL);
	if (status == SGX_ERROR_INVALID_ENCLAVE)
	{
		printf("\nApp: error invalid enclave\n", status);
	}
	else if (status == SGX_ERROR_INVALID_PARAMETER)
	{
		printf("\nApp: error invalid parameter\n", status);
	}
	else if (status == SGX_ERROR_INVALID_METADATA)
	{
		printf("\nApp: error invalid metadata\n", status);
	}
	else if (status == SGX_ERROR_INVALID_VERSION)
	{
		printf("\nApp: error invalid version \n", status);
	}
	else if (status == SGX_ERROR_INVALID_SIGNATURE)
	{
		printf("\nApp: error invalid signature \n", status);
	}
	else if (status == SGX_ERROR_MEMORY_MAP_CONFLICT)
	{
		printf("\nApp: error memory map \n", status);
	}

	else if (status == SGX_ERROR_DEVICE_BUSY)
	{
		printf("\nApp: low level device is busy  \n", status);
	}

	else if (status == SGX_ERROR_SERVICE_UNAVAILABLE)
	{
		printf("\nApp: error AE service error \n", status);
	}
	else if (status == SGX_ERROR_SERVICE_TIMEOUT)
	{
		printf("\nApp: error AE service timeout error \n", status);
	}
	else if (status != SGX_SUCCESS) {
		printf("\nApp: error %#x, failed to create enclave.\n", status);
		printf(" nothing to do\n");
		return 1;
	}

	// get enclave stuff
	status = getEnclaveName(eid, retSecret, MAX_BUF_LEN);
	printf(" =>Enclave name: %s, ID: %d\n", retSecret, eid);
	// A bunch of Enclave calls (ECALL) will happen here.

	FILE * pFile;
	pFile = fopen("sealeddata.bin", "rb");
	int insize;
	uint8_t* newsealed_data = 0;
	if (pFile != NULL)
	{
		fread(&insize, sizeof(insize), 1, pFile);
		newsealed_data = (uint8_t*)malloc(insize);
		fread(newsealed_data, insize, 1, pFile);
	}
	fclose(pFile);
	//...............................................
	int len = MAX_BUF_LEN;
	printf("\nApp: Useal test:");
	//char * unsealed = new char[len+1];
	char* unsealed = new char[len + 1]; //int unsealed = 0;
	status = enclaveUnseal(eid, &ecall_status,
		(sgx_sealed_data_t*)newsealed_data, insize,
		(uint8_t*)unsealed, (uint32_t)len);
	int newlen = strlen(unsealed);

	printf(" => Unsealed data:  %s \n", unsealed);
	return 0;
}

