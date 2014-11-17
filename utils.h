unsigned long ntohlk(unsigned long source){
	unsigned long result;
	unsigned char *bytes_s;
	unsigned char *bytes_r;
	bytes_s = (unsigned char*)(&source);
	bytes_r = (unsigned char*)(&result);
	bytes_r[0] = bytes_s[3];
	bytes_r[1] = bytes_s[2];
	bytes_r[2] = bytes_s[1];
	bytes_r[3] = bytes_s[0];
	return result;
}

unsigned int ntohsk(unsigned int source){
	unsigned int result;
	unsigned char *bytes_s;
	unsigned char *bytes_r;
	bytes_s = (unsigned char*)(&source);
	bytes_r = (unsigned char*)(&result);
	bytes_r[0] = bytes_s[1];
	bytes_r[1] = bytes_s[0];
	return result;
}

unsigned char *get_next_p(unsigned char *p){
	unsigned char *pd;
	if((p + p[1] + 2)[0] != 0x30){
		return p + p[1] + 2;
	}
	else{
		pd = p + p[1] + 2;
		while(pd[0] == 0x30){
			pd += 2;
		}
		return pd;
	}
}
