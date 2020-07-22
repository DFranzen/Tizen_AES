

//
/* parameters for the encryption */
#define AES_KEY_ALIAS "AESkey"
#define AES_KEY_SIZE 256
#define AES_KEY_PHRASE "taPt1aJ2Y69BJaK7Jnho"

#define AES_OK 0
#define AES_UNKNOWN_ERROR 1

int _AES_randIV(ckmc_raw_buffer_s *dest)
{
	for (int i=0; i<dest->size; i++)
	{
		dest->data[i] = rand();
	}

	return AES_OK;
}

char* _AES_encode(ckmc_raw_buffer_s buf)
{
	int length = buf.size;
	char* back = (char *) calloc(length*2+1, sizeof(char));
	for (int i=0;i<length;i++) {
		sprintf(&back[i*2],"%02x",buf.data[i]);
	}
	return back;
}

char* _AES_buf2string(ckmc_raw_buffer_s in)
{
	int length = in.size;
    char* back = (char *) calloc(length+1, sizeof(char));
	for (int i = 0; i<length; i++) {
		back[i] = (char)((int) in.data[i])-128;
	}
	return back;
}

ckmc_raw_buffer_s _AES_decode(char* in)
{
	ckmc_raw_buffer_s back;
	int length = strlen(in)/2;
	back.size = length;
	back.data = (unsigned char *) calloc(length, sizeof(char));

	char letter[3];
	for (int i=0;i<length;i++) {
		strncpy(letter,in+2*i,2);
		letter[2]="\0";
		back.data[i] = (char) strtol(letter, NULL, 16);
	}
	return back;
}

ckmc_raw_buffer_s _AES_string2buf(char* in)
{
    ckmc_raw_buffer_s back;
    int length = strlen(in);
    back.size = length;
    back.data = (unsigned char *) calloc(length, sizeof(char));
	for (int i = 0; i<length; i++) {
		back.data[i] = in[i]+128;
	}
	return back;
}



//
int AES_init()
{
    /* check/generate the key for encryption */
	ckmc_policy_s pol;
	pol.password = AES_KEY_PHRASE;
	pol.extractable = false;
	int ret = ckmc_create_key_aes(AES_KEY_SIZE, AES_KEY_ALIAS, pol);

	srand ((unsigned int) time (NULL));

    return AES_OK;
}
//
int AES_encrypt_string(char* in, char** out)
{
	/* encode String as buffer */
    ckmc_raw_buffer_s in_buf = _AES_string2buf(in);

    /* set encryption parameters */
	ckmc_param_list_h params;
	int ret = ckmc_generate_new_params(CKMC_ALGO_AES_CBC,&params);

	ckmc_raw_buffer_s IV;
	unsigned char buf[16];
	IV.data = buf;
	IV.size = 16;
	_AES_randIV(&IV);
	ret = ckmc_param_list_set_buffer(params,CKMC_PARAM_ED_IV,&IV);

	/* encrypt buffer */
	ckmc_raw_buffer_s *out_buf;
	ret = ckmc_encrypt_data(params,AES_KEY_ALIAS,AES_KEY_PHRASE,in_buf,&out_buf);
	free(in_buf.data);

	/* encode buffer as string */
	char *out_str = _AES_encode(*out_buf);
	char *IV_str  = _AES_encode(IV);

	/* compose result */
	char *result;
	result = (char *) calloc((out_buf->size+IV.size)*2+2, sizeof(char));
	sprintf(result,"%s|%s",out_str,IV_str);

	free(out_str);
	free(IV_str);

	*out = result;

	return AES_OK;
}
//

int AES_decrypt_string(char *in, char** out)
{
	int ret;

	// decompose data
	char *in_str = strtok(in,"|");
	char *IV_str = strtok(NULL,"|");

	// decode data to buffer
	ckmc_raw_buffer_s in_buf = _AES_decode(in_str);

	// decode IV to buffer
	ckmc_raw_buffer_s IV = _AES_decode(IV_str);

	// set encryption parameters
	/* set encryption parameters */
	ckmc_param_list_h params;
	ret = ckmc_generate_new_params(CKMC_ALGO_AES_CBC,&params);
	ret = ckmc_param_list_set_buffer(params,CKMC_PARAM_ED_IV,&IV);

	// decrypt buffer
	ckmc_raw_buffer_s* out_buf;
	ret = ckmc_decrypt_data(params, AES_KEY_ALIAS, AES_KEY_PHRASE, in_buf, &out_buf);

	// decode buffer to string
	*out = _AES_buf2string(*out_buf);

	return AES_OK;
}
